package ai.sendscore;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/** The sendscore.verdict/v1 report. Unknown fields are ignored, since the schema may add them. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Verdict(
    String schema,
    String id,
    Message message,
    String publication,
    String verdict,
    @JsonProperty("ready_to_send") boolean readyToSend,
    String summary,
    @JsonProperty("top_fixes") List<TopFix> topFixes,
    List<Check> checks,
    List<Change> changes,
    Fingerprint fingerprint,
    String explanation,
    String note) {

  /** What was checked. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Message(
      @JsonProperty("received_at") String receivedAt,
      String from,
      String subject,
      @JsonProperty("message_id") String messageId,
      @JsonProperty("size_bytes") long sizeBytes) {}

  /** What to change, and who can change it: "you" or "provider". */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Fix(String who, String text) {}

  /** One rule applied to the message, with the evidence it looked at. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Check(
      String id,
      String category,
      String status,
      String title,
      String detail,
      Map<String, Object> evidence,
      Fix fix,
      String docs,
      String reason) {}

  /** One of the fixes to make first. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record TopFix(String check, String who, String fix) {}

  /** One difference from the previous issue. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Change(String field, Object before, Object after, String worsened) {}

  /** What the comparison looks at. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Fingerprint(
      @JsonProperty("dkim_domains") List<String> dkimDomains,
      @JsonProperty("dkim_selectors") List<String> dkimSelectors,
      @JsonProperty("return_path_domain") String returnPathDomain,
      @JsonProperty("remote_ip") String remoteIp,
      String ptr,
      @JsonProperty("list_unsubscribe") boolean listUnsubscribe,
      @JsonProperty("one_click") boolean oneClick,
      @JsonProperty("link_hosts") List<String> linkHosts,
      @JsonProperty("html_bytes") long htmlBytes,
      long links,
      long images,
      Map<String, String> auth) {}

  /** The differences between two saved messages. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record Diff(String before, String after, List<Change> changes) {}
}
