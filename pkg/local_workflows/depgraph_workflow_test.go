package localworkflows

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Depgraph_extractLegacyCLIError_extractError(t *testing.T) {

	expectedMsgJson := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "something"), "application/json", []byte(expectedMsgJson))

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, "Hello Error", outputError.Error())

	_, ok := outputError.(*LegacyCliJsonError)
	assert.True(t, ok)
}

func Test_Depgraph_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, inputError.Error(), outputError.Error())
}

func Test_Depgraph_InitDepGraphWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := workflow.Register(OpenSourceDepGraph, engine)
	assert.Nil(t, err)

	allProjects := config.Get("all-projects")
	assert.Equal(t, false, allProjects)

	inputFile := config.Get("file")
	assert.Equal(t, "", inputFile)
}

func TestLegacyCLIInvocation(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	ctrl := gomock.NewController(t)

	type testCase struct {
		workflow workflow.WorkflowRegisterer
		cmdArgs  []string
	}
	testCases := map[string]testCase{
		"open-source": {
			workflow: OpenSourceDepGraph,
			cmdArgs:  []string{"test", "--print-graph", "--json"},
		},
		"container": {
			workflow: ContainerDepGraph,
			cmdArgs:  []string{"container", "test", "--print-graph", "--json"},
		}}

	for tcName, tc := range testCases {
		t.Run(tcName, func(t *testing.T) {
			config := configuration.New()
			engineMock := mocks.NewMockEngine(ctrl)
			invocationContextMock := mocks.NewMockInvocationContext(ctrl)
			config.Set("targetDirectory", ".")

			// invocation context mocks
			invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
			invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
			invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
			dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
			data := workflow.NewData(dataIdentifier, "application/json", []byte(nil))

			// engine mocks
			id := workflow.NewWorkflowIdentifier("legacycli")
			engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

			// execute
			// we always expect an error because we don't return a depGraph from the legacycli call.
			_, err := tc.workflow.Entrypoint(invocationContextMock, []workflow.Data{})
			require.ErrorAs(t, err, &noDependencyGraphsError{})

			assert.Equal(t,
				append(tc.cmdArgs, "."),
				config.Get(configuration.RAW_CMD_ARGS),
			)
		})
	}
}

func TestDepGraphArgs(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	ctrl := gomock.NewController(t)

	f := OpenSourceDepGraph.Flags()
	type testCase struct {
		arg      string
		value    interface{}
		expected string
	}
	testCases := []testCase{{
		arg:      f.Debug.Name,
		expected: "--debug",
		value:    true,
	}, {
		arg:      f.AllProjects.Name,
		expected: "--all-projects",
		value:    true,
	}, {
		arg:      f.Dev.Name,
		expected: "--dev",
		value:    true,
	}, {
		arg:      f.FailFast.Name,
		expected: "--fail-fast",
		value:    true,
	}, {
		arg:      f.AllProjects.Name,
		expected: "--all-projects",
		value:    true,
	}, {
		arg:      f.File.Name,
		expected: "--file=path/to/target/file.js",
		value:    "path/to/target/file.js",
	}, {
		arg:      f.Exclude.Name,
		expected: "--exclude=path/to/target/file.js",
		value:    "path/to/target/file.js",
	}, {
		arg:      f.DetectionDepth.Name,
		expected: "--detection-depth=42",
		value:    "42",
	}, {
		arg:      f.PruneRepeatedSubdependencies.Name,
		expected: "--prune-repeated-subdependencies",
		value:    true,
	}, {
		arg:      "targetDirectory",
		expected: "path/to/target",
		value:    "path/to/target",
	}}

	for _, tc := range testCases {
		t.Run("test flag "+tc.arg, func(t *testing.T) {
			// setup a clean slate for every test.
			config := configuration.New()
			engineMock := mocks.NewMockEngine(ctrl)
			invocationContextMock := mocks.NewMockInvocationContext(ctrl)

			// invocation context mocks
			invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
			invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
			invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
			config.Set(tc.arg, tc.value)
			dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
			data := workflow.NewData(dataIdentifier, "application/json", []byte(nil))

			// engine mocks
			id := workflow.NewWorkflowIdentifier("legacycli")
			engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

			// execute
			// we always expect an error because we don't return a depGraph from the legacycli call.
			_, err := OpenSourceDepGraph.Entrypoint(invocationContextMock, []workflow.Data{})
			require.ErrorAs(t, err, &noDependencyGraphsError{})

			commandArgs := config.Get(configuration.RAW_CMD_ARGS)
			assert.Contains(t, commandArgs, tc.expected)
		})
	}

}

func TestExtractDepGraphsFromCLIOutput(t *testing.T) {
	type depGraph struct {
		name string
		file string
	}
	type testCase struct {
		cliOutputFile string
		graphs        []depGraph
	}

	testCases := []testCase{{
		cliOutputFile: "testdata/opensource_scan_output.txt",
		graphs: []depGraph{{
			name: "package-lock.json",
			file: "testdata/opensource_scan_depgraph.json",
		}},
	}, {
		cliOutputFile: "testdata/container_scan_output.txt",
		graphs: []depGraph{{
			name: "docker-image|snyk/kubernetes-scanner",
			file: "testdata/container_scan_depgraph_os.json",
		}, {
			name: "docker-image|snyk/kubernetes-scanner:/kubernetes-scanner",
			file: "testdata/container_scan_depgraph_app.json",
		}},
	}}

	for _, tc := range testCases {
		t.Run(tc.cliOutputFile, func(t *testing.T) {
			output, err := os.ReadFile(tc.cliOutputFile)
			require.NoError(t, err)

			data, err := extractDepGraphsFromCLIOutput(output)
			require.NoError(t, err)

			require.Len(t, data, len(tc.graphs))
			var i int
			for _, graph := range tc.graphs {
				require.NoError(t, testDepGraphFromFile(graph.name, graph.file, data[i]))
				i++
			}
		})
	}

}

func testDepGraphFromFile(dgName string, fileName string, actual workflow.Data) error {
	content, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("could not read testdata file: %w", err)
	}

	var expectedDG map[string]interface{}
	if err := json.Unmarshal(content, &expectedDG); err != nil {
		return fmt.Errorf("could not marshal JSON: %w", err)
	}

	if actual.GetContentType() != depGraphContentType {
		return fmt.Errorf("content types do not match. expected=%q, got=%q",
			depGraphContentType, actual.GetContentType())
	}

	if actual.GetContentLocation() != dgName {
		return fmt.Errorf("content locations (names) do not match. expected=%q, got=%q",
			dgName, actual.GetContentLocation())
	}

	var actualDG map[string]interface{}
	if err := json.Unmarshal(actual.GetPayload().([]byte), &actualDG); err != nil {
		return fmt.Errorf("could not unmarshal actual DepGraph's JSON: %w", err)
	}
	if !reflect.DeepEqual(actualDG, expectedDG) {
		return fmt.Errorf("depGraphs are not equal: expected=%+v\nactual=%+v", expectedDG, actualDG)
	}
	return nil
}
