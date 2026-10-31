/** The `sendscore.verdict/v1` report. New fields may appear in this version. */

export type Status = "pass" | "warn" | "fail" | "info" | "skipped";
export type Category = "auth" | "unsub" | "struct" | "content" | "delivery" | "changes";
export type Who = "you" | "provider";

export interface Message {
  received_at: string;
  from: string;
  subject: string;
  message_id: string;
  size_bytes: number;
}

export interface Fix {
  who: Who;
  text: string;
}

export interface Check {
  id: string;
  category: Category;
  status: Status;
  title: string;
  detail?: string;
  evidence?: Record<string, unknown>;
  fix?: Fix;
  docs?: string;
  /** Why the check was skipped. */
  reason?: string;
}

export interface TopFix {
  check: string;
  who: Who;
  fix: string;
}

export interface Change {
  field: string;
  before: unknown;
  after: unknown;
  /** The check this change made worse, if any. */
  worsened?: string;
}

export interface Fingerprint {
  dkim_domains: string[];
  dkim_selectors: string[];
  return_path_domain: string;
  remote_ip?: string;
  ptr?: string;
  list_unsubscribe: boolean;
  one_click: boolean;
  link_hosts: string[];
  html_bytes: number;
  links: number;
  images: number;
  auth: Record<string, Status> | null;
}

export interface Verdict {
  schema: string;
  id?: string;
  message: Message;
  publication?: string;
  verdict: Status;
  ready_to_send: boolean;
  summary: string;
  top_fixes: TopFix[];
  checks: Check[];
  changes: Change[];
  fingerprint?: Fingerprint;
  explanation: string | null;
  note: string;
}

export interface DiffResult {
  before: string;
  after: string;
  changes: Change[];
}

export interface CheckOptions {
  /** Make no DNS lookups. Checks that need DNS are skipped. */
  offline?: boolean;
  /** Fetch every link and image, never unsubscribe or confirm links. */
  links?: boolean;
  /** IP address of the server that delivered the message. */
  ip?: string;
  /** Envelope sender. Defaults to the Return-Path. */
  mailFrom?: string;
  /** HELO name the delivering server gave. */
  helo?: string;
  /** Whether delivery used TLS. */
  tls?: boolean;
  /** Path of the publication's previous issue, to list what changed. */
  previous?: string;
  /** Kill the CLI and throw after this many milliseconds. No limit by default. */
  timeout?: number;
}

/** What a comparison should do beyond reading the messages. */
export interface DiffOptions {
  /** Kill the CLI and throw after this many milliseconds. No limit by default. */
  timeout?: number;
}
