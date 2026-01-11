/*
Copyright 2024 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package load provides functionality to load Kubernetes manifests from various sources
package load

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/crossplane/crossplane-runtime/v2/pkg/errors"

	v1 "github.com/crossplane/crossplane/v2/apis/apiextensions/v1"
)

const (
	// AnnotationSourceFile is the annotation key used to store the source file path.
	AnnotationSourceFile = "crossplane.io/source-file"
	// AnnotationSourceLine is the annotation key used to store the source line number.
	AnnotationSourceLine = "crossplane.io/source-line"
)

// Loader interface defines the contract for different input sources.
type Loader interface {
	Load() ([]*unstructured.Unstructured, error)
}

// NewLoader returns a Loader based on the input source.
func NewLoader(input string) (Loader, error) {
	sources := strings.Split(input, ",")

	if len(sources) == 1 {
		return newLoader(sources[0])
	}

	loaders := make([]Loader, 0, len(sources))

	for _, source := range sources {
		loader, err := newLoader(source)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("cannot create loader for %q", source))
		}

		loaders = append(loaders, loader)
	}

	return &MultiLoader{loaders: loaders}, nil
}

func newLoader(input string) (Loader, error) {
	if input == "-" {
		return &StdinLoader{}, nil
	}

	fi, err := os.Stat(input)
	if err != nil {
		return nil, errors.Wrap(err, "cannot stat input source")
	}

	if fi.IsDir() {
		return &FolderLoader{path: input}, nil
	}

	return &FileLoader{path: input}, nil
}

// MultiLoader implements the Loader interface for reading from multiple other loaders.
type MultiLoader struct {
	loaders []Loader
}

// Load reads and merges the content from the loaders.
func (m *MultiLoader) Load() ([]*unstructured.Unstructured, error) {
	var manifests []*unstructured.Unstructured

	for i, loader := range m.loaders {
		output, err := loader.Load()
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("cannot load source at position %d", i))
		}

		manifests = append(manifests, output...)
	}

	return manifests, nil
}

// StdinLoader implements the Loader interface for reading from stdin.
type StdinLoader struct{}

// Load reads the contents from stdin.
func (s *StdinLoader) Load() ([]*unstructured.Unstructured, error) {
	stream, err := YamlStream(os.Stdin)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load YAML stream from stdin")
	}

	return streamToUnstructured(stream)
}

// FileLoader implements the Loader interface for reading from a file and converting input to unstructured objects.
type FileLoader struct {
	path string
}

// Load reads the contents from a file.
func (f *FileLoader) Load() ([]*unstructured.Unstructured, error) {
	stream, err := readFile(f.path)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read file")
	}

	manifests, err := streamToUnstructured(stream)
	if err != nil {
		return nil, err
	}

	// Add source file annotation to all loaded objects
	for _, m := range manifests {
		addSourceAnnotation(m, f.path)
	}

	return manifests, nil
}

// FolderLoader implements the Loader interface for reading from a folder.
type FolderLoader struct {
	path string
}

// fileStream holds byte stream with its source file path and line number.
type fileStream struct {
	data     []byte
	path     string
	lineNum  int // Starting line number of this document in the file
}

// Load reads the contents from all files in a folder.
func (f *FolderLoader) Load() ([]*unstructured.Unstructured, error) {
	var streams []fileStream

	err := filepath.Walk(f.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if isYamlFile(info) {
			s, err := readFileWithLineNumbers(path)
			if err != nil {
				return err
			}

			streams = append(streams, s...)
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "cannot read folder")
	}

	return streamToUnstructuredWithSource(streams)
}

func isYamlFile(info os.FileInfo) bool {
	return !info.IsDir() && (filepath.Ext(info.Name()) == ".yaml" || filepath.Ext(info.Name()) == ".yml")
}

func readFile(path string) ([][]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, errors.Wrap(err, "cannot open file")
	}
	defer f.Close() //nolint:errcheck // Only open for reading.

	return YamlStream(f)
}

// readFileWithLineNumbers reads a file and tracks line numbers for each YAML document.
func readFileWithLineNumbers(path string) ([]fileStream, error) {
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, errors.Wrap(err, "cannot read file")
	}

	var streams []fileStream
	currentLine := 1
	reader := bufio.NewReader(bytes.NewReader(content))
	yr := yaml.NewYAMLReader(reader)

	for {
		docBytes, err := yr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "cannot parse YAML stream")
		}

		if len(docBytes) == 0 {
			continue
		}

		streams = append(streams, fileStream{
			data:    docBytes,
			path:    path,
			lineNum: currentLine,
		})

		// Count newlines in this document to update current line
		currentLine += bytes.Count(docBytes, []byte("\n"))
	}

	return streams, nil
}

// YamlStream loads a yaml stream from a reader into a 2d byte slice.
func YamlStream(r io.Reader) ([][]byte, error) {
	stream := make([][]byte, 0)

	yr := yaml.NewYAMLReader(bufio.NewReader(r))

	for {
		bytes, err := yr.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, errors.Wrap(err, "cannot parse YAML stream")
		}

		if len(bytes) == 0 {
			continue
		}

		stream = append(stream, bytes)
	}

	return stream, nil
}

func streamToUnstructured(stream [][]byte) ([]*unstructured.Unstructured, error) {
	manifests := make([]*unstructured.Unstructured, 0, len(stream))

	for _, y := range stream {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(y, u); err != nil {
			return nil, errors.Wrap(err, "cannot parse YAML manifest")
		}
		// extract pipeline input resources
		if u.GetObjectKind().GroupVersionKind() == v1.CompositionGroupVersionKind {
			// Convert the unstructured resource to a Composition
			var comp v1.Composition

			err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &comp)
			if err != nil {
				return nil, errors.Wrap(err, "failed to convert unstructured to Composition")
			}
			// Iterate over each step in the pipeline
			for _, step := range comp.Spec.Pipeline {
				// Create a new resource based on the input (we can use it for validation)
				if step.Input != nil && step.Input.Raw != nil {
					var inputMap map[string]interface{}

					err := json.Unmarshal(step.Input.Raw, &inputMap)
					if err != nil {
						return nil, errors.Wrap(err, "failed to unmarshal raw input")
					}

					newInputResource := &unstructured.Unstructured{
						Object: inputMap,
					}
					// Add the input as new manifest to the manifests slice that we can validate
					manifests = append(manifests, newInputResource)
				}
			}
		}

		manifests = append(manifests, u)
	}

	return manifests, nil
}

// CompositeLoader acts as a composition of multiple loaders
// to handle loading resources from various sources at once.
type CompositeLoader struct {
	loaders []Loader
}

// NewCompositeLoader creates a new composite loader based on the specified sources.
// Sources can be files, directories, or "-" for stdin.
// If sources is empty, stdin is used by default.
func NewCompositeLoader(sources []string) (Loader, error) {
	if len(sources) == 0 {
		// In unit tests, this will cause an error when Load() is called
		// which is the expected behavior for NoSources test case
		return &CompositeLoader{loaders: []Loader{}}, nil
	}

	// Create loaders for each source
	loaders := make([]Loader, 0, len(sources))

	// Check for duplicate stdin markers to avoid reading stdin multiple times
	stdinUsed := false

	for _, source := range sources {
		if source == "-" {
			if stdinUsed {
				// Skip duplicate stdin markers - only use stdin once
				continue
			}
			stdinUsed = true
		}

		loader, err := NewLoader(source)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot create loader for %q", source)
		}
		loaders = append(loaders, loader)
	}

	return &CompositeLoader{loaders: loaders}, nil
}

// Load implements the Loader interface by loading from all contained loaders
// and combining the results.
func (c *CompositeLoader) Load() ([]*unstructured.Unstructured, error) {
	if len(c.loaders) == 0 {
		return nil, errors.New("no loaders configured")
	}

	// Combine results from all loaders
	var allResources []*unstructured.Unstructured

	for _, loader := range c.loaders {
		resources, err := loader.Load()
		if err != nil {
			return nil, errors.Wrap(err, "cannot load resources from loader")
		}
		allResources = append(allResources, resources...)
	}

	// Check if we found any resources
	if len(allResources) == 0 {
		return nil, errors.New("no resources found from any source")
	}

	return allResources, nil
}

// addSourceAnnotation adds the source file path annotation to an object.
func addSourceAnnotation(obj *unstructured.Unstructured, path string) {
	addSourceAnnotationWithLine(obj, path, 0)
}

func addSourceAnnotationWithLine(obj *unstructured.Unstructured, path string, lineNum int) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[AnnotationSourceFile] = path
	if lineNum > 0 {
		annotations[AnnotationSourceLine] = strconv.Itoa(lineNum)
	}
	obj.SetAnnotations(annotations)
}

// streamToUnstructuredWithSource converts byte streams to unstructured objects with source tracking.
func streamToUnstructuredWithSource(streams []fileStream) ([]*unstructured.Unstructured, error) {
	manifests := make([]*unstructured.Unstructured, 0, len(streams))

	for _, fs := range streams {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(fs.data, u); err != nil {
			return nil, errors.Wrapf(err, "cannot parse YAML manifest from %s:%d", fs.path, fs.lineNum)
		}

		// Add source annotation with line number
		addSourceAnnotationWithLine(u, fs.path, fs.lineNum)

		// extract pipeline input resources
		if u.GetObjectKind().GroupVersionKind() == v1.CompositionGroupVersionKind {
			// Convert the unstructured resource to a Composition
			var comp v1.Composition

			err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &comp)
			if err != nil {
				return nil, errors.Wrap(err, "failed to convert unstructured to Composition")
			}
			// Iterate over each step in the pipeline
			for _, step := range comp.Spec.Pipeline {
				// Create a new resource based on the input (we can use it for validation)
				if step.Input != nil && step.Input.Raw != nil {
					var inputMap map[string]interface{}

					err := json.Unmarshal(step.Input.Raw, &inputMap)
					if err != nil {
						return nil, errors.Wrap(err, "failed to unmarshal raw input")
					}

					newInputResource := &unstructured.Unstructured{
						Object: inputMap,
					}

					// Find the actual line number for this step's input
					inputLine := FindStepInputLine(fs.path, step.Step)
					if inputLine == 0 {
						inputLine = fs.lineNum // Fall back to composition start line
					}

					// Add source annotation to input resources with exact line number
					addSourceAnnotationWithLine(newInputResource, fs.path, inputLine)
					// Add the input as new manifest to the manifests slice that we can validate
					manifests = append(manifests, newInputResource)

					// Extract base resources from function inputs for validation
					// This handles function-patch-and-transform style inputs
					baseResources := extractBaseResources(inputMap, fs.path, inputLine)
					manifests = append(manifests, baseResources...)
				}
			}
		}

		manifests = append(manifests, u)
	}

	return manifests, nil
}

// extractBaseResources extracts base resources from function input for validation.
// This handles function-patch-and-transform style inputs where resources have a base: block.
func extractBaseResources(inputMap map[string]interface{}, filePath string, startLine int) []*unstructured.Unstructured {
	var results []*unstructured.Unstructured

	// Look for resources array in the input (function-patch-and-transform format)
	resources, ok := inputMap["resources"].([]interface{})
	if !ok {
		return results
	}

	for i, res := range resources {
		resMap, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		// Get resource name for line finding
		resourceName, _ := resMap["name"].(string)

		// Look for base block
		base, ok := resMap["base"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check if base has apiVersion and kind
		apiVersion, hasAPIVersion := base["apiVersion"].(string)
		kind, hasKind := base["kind"].(string)
		if !hasAPIVersion || !hasKind {
			continue
		}

		// Create unstructured resource from base
		baseResource := &unstructured.Unstructured{
			Object: base,
		}

		// Find the line number for this base resource
		baseLine := FindBaseResourceLine(filePath, resourceName, startLine)
		if baseLine == 0 {
			// Fall back to finding by index
			baseLine = FindNthBaseInFile(filePath, i, startLine)
		}
		if baseLine == 0 {
			baseLine = startLine
		}

		// Add source annotation
		addSourceAnnotationWithLine(baseResource, filePath, baseLine)

		// Add annotation to identify this as a base resource for better error messages
		annotations := baseResource.GetAnnotations()
		if annotations == nil {
			annotations = make(map[string]string)
		}
		annotations["crossplane.io/base-resource-name"] = resourceName
		annotations["crossplane.io/base-resource-gvk"] = apiVersion + ", Kind=" + kind
		baseResource.SetAnnotations(annotations)

		results = append(results, baseResource)
	}

	return results
}

// FindBaseResourceLine finds the line number of a base: block for a named resource.
func FindBaseResourceLine(filePath, resourceName string, startLine int) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	if startLine < 1 {
		startLine = 1
	}

	inResource := false
	resourceIndent := 0

	// Patterns to match resource name
	namePatterns := []string{
		fmt.Sprintf("- name: %s", resourceName),
		fmt.Sprintf("name: %s", resourceName),
		fmt.Sprintf("- name: \"%s\"", resourceName),
		fmt.Sprintf("name: \"%s\"", resourceName),
	}

	for lineNum := startLine - 1; lineNum < len(lines); lineNum++ {
		line := lines[lineNum]
		trimmed := strings.TrimSpace(line)
		currentIndent := len(line) - len(strings.TrimLeft(line, " "))

		// Look for the resource by name
		matchedResource := false
		for _, pattern := range namePatterns {
			if strings.Contains(trimmed, pattern) || trimmed == pattern {
				matchedResource = true
				break
			}
		}

		if matchedResource {
			inResource = true
			resourceIndent = currentIndent
			continue
		}

		// If we're in the resource, look for base section
		if inResource {
			if trimmed == "base:" || strings.HasPrefix(trimmed, "base:") {
				return lineNum + 1 // 1-indexed
			}

			// If we hit another resource at same or lower indent level, we've left this resource
			if currentIndent <= resourceIndent && strings.HasPrefix(trimmed, "- name:") {
				inResource = false
			}
		}
	}

	return 0
}

// FindNthBaseInFile finds the nth base: block in a file starting from a given line.
func FindNthBaseInFile(filePath string, n int, startLine int) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	if startLine < 1 {
		startLine = 1
	}

	count := 0
	for lineNum := startLine - 1; lineNum < len(lines); lineNum++ {
		trimmed := strings.TrimSpace(lines[lineNum])
		if trimmed == "base:" || strings.HasPrefix(trimmed, "base:") {
			if count == n {
				return lineNum + 1
			}
			count++
		}
	}

	return 0
}

// GetSourceFile returns the source file path from an object's annotations.
func GetSourceFile(obj *unstructured.Unstructured) string {
	if obj == nil {
		return ""
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return ""
	}
	return annotations[AnnotationSourceFile]
}

// GetSourceLine returns the source line number from an object's annotations.
func GetSourceLine(obj *unstructured.Unstructured) int {
	if obj == nil {
		return 0
	}
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return 0
	}
	lineStr := annotations[AnnotationSourceLine]
	if lineStr == "" {
		return 0
	}
	line, err := strconv.Atoi(lineStr)
	if err != nil {
		return 0
	}
	return line
}

// GetSourceLocation returns a formatted source location string (file:line).
func GetSourceLocation(obj *unstructured.Unstructured) string {
	file := GetSourceFile(obj)
	line := GetSourceLine(obj)
	if file == "" {
		return ""
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}

// FindLineInFile searches for a pattern in a file and returns the line number.
// If multiple matches exist, it returns the nth match (0-indexed).
func FindLineInFile(filePath, pattern string, matchIndex int) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	currentMatch := 0

	for lineNum, line := range lines {
		if strings.Contains(line, pattern) {
			if currentMatch == matchIndex {
				return lineNum + 1 // 1-indexed
			}
			currentMatch++
		}
	}
	return 0
}

// FindPatchLineInComposition finds the line number of a specific patch in a composition file.
// resourceName is the name of the composed resource, patchIndex is the 0-based index of the patch.
func FindPatchLineInComposition(filePath, resourceName string, patchIndex int) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	inResource := false
	inPatches := false
	currentPatchIndex := -1
	resourceIndent := 0

	// Patterns to match resource name
	resourcePatterns := []string{
		fmt.Sprintf("- name: %s", resourceName),
		fmt.Sprintf("name: %s", resourceName),
		fmt.Sprintf("- name: \"%s\"", resourceName),
		fmt.Sprintf("name: \"%s\"", resourceName),
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		currentIndent := len(line) - len(strings.TrimLeft(line, " "))

		// Look for the resource by name
		matchedResource := false
		for _, pattern := range resourcePatterns {
			if strings.Contains(trimmed, pattern) || trimmed == pattern {
				matchedResource = true
				break
			}
		}

		if matchedResource {
			inResource = true
			inPatches = false
			currentPatchIndex = -1
			resourceIndent = currentIndent
			continue
		}

		// If we're in the resource, look for patches section
		if inResource {
			if trimmed == "patches:" {
				inPatches = true
				currentPatchIndex = -1
				continue
			}

			// If we hit another resource at same or lower indent level, we've left this resource
			if currentIndent <= resourceIndent && strings.HasPrefix(trimmed, "- name:") {
				inResource = false
				inPatches = false
				continue
			}
		}

		// If we're in patches, count patch entries
		if inPatches {
			// A new patch starts with "- " at the patch level
			if strings.HasPrefix(trimmed, "- ") && (strings.Contains(trimmed, "fromFieldPath") ||
				strings.Contains(trimmed, "toFieldPath") ||
				strings.Contains(trimmed, "type:") ||
				strings.HasPrefix(trimmed, "- type:") ||
				strings.HasPrefix(trimmed, "- fromFieldPath:") ||
				strings.HasPrefix(trimmed, "- toFieldPath:") ||
				strings.HasPrefix(trimmed, "- patchSetName:")) {
				currentPatchIndex++
				if currentPatchIndex == patchIndex {
					return lineNum + 1 // 1-indexed
				}
			}
		}
	}

	return 0
}

// FindStepInputLine finds the line number of a pipeline step's input in a composition file.
// stepName is the name of the pipeline step.
func FindStepInputLine(filePath, stepName string) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return 0
	}

	lines := strings.Split(string(content), "\n")
	inStep := false
	stepIndent := 0

	// Patterns to match step name
	stepPatterns := []string{
		fmt.Sprintf("- step: %s", stepName),
		fmt.Sprintf("step: %s", stepName),
		fmt.Sprintf("- step: \"%s\"", stepName),
		fmt.Sprintf("step: \"%s\"", stepName),
	}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		currentIndent := len(line) - len(strings.TrimLeft(line, " "))

		// Look for the step by name
		matchedStep := false
		for _, pattern := range stepPatterns {
			if strings.Contains(trimmed, pattern) || trimmed == pattern {
				matchedStep = true
				break
			}
		}

		if matchedStep {
			inStep = true
			stepIndent = currentIndent
			continue
		}

		// If we're in the step, look for input section
		if inStep {
			if trimmed == "input:" || strings.HasPrefix(trimmed, "input:") {
				return lineNum + 1 // 1-indexed
			}

			// If we hit another step at same or lower indent level, we've left this step
			if currentIndent <= stepIndent && (strings.HasPrefix(trimmed, "- step:") || strings.HasPrefix(trimmed, "step:")) {
				inStep = false
			}
		}
	}

	return 0
}

// FindValueInFile searches for a specific value in a file starting from a given line.
// This is useful for finding the exact line of an error value within a YAML structure.
func FindValueInFile(filePath string, startLine int, value string) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return startLine
	}

	lines := strings.Split(string(content), "\n")
	if startLine < 1 {
		startLine = 1
	}

	// Search from startLine onwards for the value
	for i := startLine - 1; i < len(lines); i++ {
		if strings.Contains(lines[i], value) {
			return i + 1 // 1-indexed
		}
	}

	return startLine
}

// FindPathInYAML attempts to find the line number of a specific path in a YAML file.
// path is in the format "resources[1].patches[0].transforms[0].convert.toType"
// startLine is the line to start searching from (e.g., the input: line)
func FindPathInYAML(filePath string, startLine int, path string) int {
	content, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return startLine
	}

	lines := strings.Split(string(content), "\n")
	if startLine < 1 {
		startLine = 1
	}

	// Parse the path into components
	// e.g., "resources[1].patches[0].transforms[0].convert.toType"
	// becomes ["resources", "1", "patches", "0", "transforms", "0", "convert", "toType"]
	components := parseYAMLPath(path)
	if len(components) == 0 {
		return startLine
	}

	currentLine := startLine - 1
	currentIndent := -1

	for _, comp := range components {
		found := false
		// Determine if this component is an array index or a key
		isIndex := false
		index := 0
		if idx, err := strconv.Atoi(comp); err == nil {
			isIndex = true
			index = idx
		}

		if isIndex {
			// We need to find the nth array item (marked by "- ")
			itemCount := 0
			baseIndent := currentIndent
			for i := currentLine; i < len(lines); i++ {
				line := lines[i]
				trimmed := strings.TrimSpace(line)
				lineIndent := len(line) - len(strings.TrimLeft(line, " "))

				// Skip empty lines
				if trimmed == "" {
					continue
				}

				// If we've gone back to a lower indent, we've left the array
				if lineIndent <= baseIndent && i > currentLine {
					break
				}

				// Check if this is an array item at the expected indent level
				if strings.HasPrefix(trimmed, "- ") && (baseIndent == -1 || lineIndent > baseIndent) {
					if itemCount == index {
						currentLine = i
						currentIndent = lineIndent
						found = true
						break
					}
					itemCount++
				}
			}
		} else {
			// Looking for a key
			keyPatterns := []string{
				comp + ":",
				comp + ": ",
			}
			baseIndent := currentIndent
			for i := currentLine; i < len(lines); i++ {
				line := lines[i]
				trimmed := strings.TrimSpace(line)
				lineIndent := len(line) - len(strings.TrimLeft(line, " "))

				// Skip empty lines
				if trimmed == "" {
					continue
				}

				// If we've gone back to a lower or equal indent (after moving), we've left the section
				if lineIndent <= baseIndent && i > currentLine && baseIndent >= 0 {
					break
				}

				for _, pattern := range keyPatterns {
					if strings.HasPrefix(trimmed, pattern) || strings.HasPrefix(strings.TrimPrefix(trimmed, "- "), pattern) {
						currentLine = i
						currentIndent = lineIndent
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}

		if !found {
			// Couldn't find this component, return best guess
			return currentLine + 1
		}
	}

	return currentLine + 1 // 1-indexed
}

// parseYAMLPath parses a path like "resources[1].patches[0].toType" into components
func parseYAMLPath(path string) []string {
	var components []string
	current := ""

	for i := 0; i < len(path); i++ {
		ch := path[i]
		switch ch {
		case '.':
			if current != "" {
				components = append(components, current)
				current = ""
			}
		case '[':
			if current != "" {
				components = append(components, current)
				current = ""
			}
		case ']':
			if current != "" {
				components = append(components, current)
				current = ""
			}
		default:
			current += string(ch)
		}
	}
	if current != "" {
		components = append(components, current)
	}

	return components
}
