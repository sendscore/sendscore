package cmd

import (
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/sendscore/sendscore/mcpserver"
)

// defaultAppURL is the hosted app. A self-hosted instance sets SENDSCORE_URL.
const defaultAppURL = "https://app.sendscore.ai"

func newMCP() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the SendScore MCP server over stdio",
		Long: `Run SendScore's MCP tools over stdio, for Claude Code, Claude Desktop, or
any other MCP client. The tools call a SendScore app's API:

  SENDSCORE_URL     the app (default https://app.sendscore.ai)
  SENDSCORE_TOKEN   an API token, when the app requires one

Tools: get_test_address, wait_for_message, get_report, and
compare_to_previous.

Example (Claude Code):

  claude mcp add sendscore -- sendscore mcp`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			base := os.Getenv("SENDSCORE_URL")
			if base == "" {
				base = defaultAppURL
			}
			b := &mcpserver.HTTPBackend{BaseURL: base, Token: os.Getenv("SENDSCORE_TOKEN")}
			return mcpserver.New(b, resolveVersion()).Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
}
