package cmd

import (
	"fmt"
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
any other MCP client. The tools call a SendScore app's API, which needs an
API token on every request. Create one on the Account page of the app.

  SENDSCORE_TOKEN   your API token (required, starts with ss_live_)
  SENDSCORE_URL     the app (default https://app.sendscore.ai)

Tools: get_test_address, wait_for_message, get_report, and
compare_to_previous.

Example (Claude Code):

  claude mcp add sendscore --env SENDSCORE_TOKEN=ss_live_... -- sendscore mcp`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			base := os.Getenv("SENDSCORE_URL")
			if base == "" {
				base = defaultAppURL
			}
			token := os.Getenv("SENDSCORE_TOKEN")
			if token == "" {
				// stdout carries the protocol, so the warning goes to stderr,
				// which MCP clients show in their logs.
				fmt.Fprintln(cmd.ErrOrStderr(), "SENDSCORE_TOKEN is not set, so the SendScore app will refuse every tool call. Create a token on the Account page of the app and set SENDSCORE_TOKEN.")
			}
			b := &mcpserver.HTTPBackend{BaseURL: base, Token: token}
			return withCode(ExitSoftware, mcpserver.New(b, resolveVersion()).Run(cmd.Context(), &mcp.StdioTransport{}))
		},
	}
}
