import { Fragment, type ReactNode } from "react";
import { classNames } from "@/lib/utils";

/**
 * Minimal, dependency-free markdown renderer for assistant messages.
 * Supports fenced code, headings, bullet/numbered lists, blockquotes,
 * bold/italic, inline code and links — so raw "**" never reaches the user.
 */

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const pattern =
    /(`[^`\n]+`)|(\*\*\*[^*]+\*\*\*)|(\*\*[^*]+\*\*)|(__[^_]+__)|(\*[^*\n]+\*)|(_[^_\n]+_)|(\[[^\]]+\]\((https?:\/\/[^\s)]+)\))|(https?:\/\/[^\s)]+)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let i = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    const token = match[0];
    const key = `${keyPrefix}-i${i++}`;

    if (token.startsWith("`")) {
      nodes.push(
        <code key={key} className="rounded bg-ink-800/70 px-1 py-0.5 font-mono text-[12px] text-cyber-200">
          {token.slice(1, -1)}
        </code>,
      );
    } else if (token.startsWith("***")) {
      nodes.push(
        <strong key={key} className="font-semibold italic text-ink-100">
          {token.slice(3, -3)}
        </strong>,
      );
    } else if (token.startsWith("**") || token.startsWith("__")) {
      nodes.push(
        <strong key={key} className="font-semibold text-ink-100">
          {token.slice(2, -2)}
        </strong>,
      );
    } else if (token.startsWith("[")) {
      const label = token.slice(1, token.indexOf("]"));
      const href = match[8] ?? "#";
      nodes.push(
        <a key={key} href={href} target="_blank" rel="noreferrer noopener" className="text-cyber-300 underline underline-offset-2">
          {label}
        </a>,
      );
    } else if (token.startsWith("http")) {
      nodes.push(
        <a key={key} href={token} target="_blank" rel="noreferrer noopener" className="text-cyber-300 underline underline-offset-2 break-all">
          {token}
        </a>,
      );
    } else {
      nodes.push(
        <em key={key} className="italic">
          {token.slice(1, -1)}
        </em>,
      );
    }
    last = match.index + token.length;
  }

  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

interface Block {
  type: "p" | "code" | "ul" | "ol" | "h" | "quote";
  lines: string[];
  level?: number;
  lang?: string;
}

function parseBlocks(source: string): Block[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let current: Block | null = null;
  let inCode = false;

  const push = () => {
    if (current) blocks.push(current);
    current = null;
  };

  for (const raw of lines) {
    if (raw.trim().startsWith("```")) {
      if (inCode) {
        push();
        inCode = false;
      } else {
        push();
        inCode = true;
        current = { type: "code", lines: [], lang: raw.trim().slice(3).trim() || undefined };
      }
      continue;
    }

    if (inCode && current) {
      current.lines.push(raw);
      continue;
    }

    const line = raw.trimEnd();
    if (!line.trim()) {
      push();
      continue;
    }

    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    const bullet = /^\s*([-*+])\s+(.*)$/.exec(line);
    const ordered = /^\s*(\d+)[.)]\s+(.*)$/.exec(line);
    const quote = /^\s*>\s?(.*)$/.exec(line);

    if (heading) {
      push();
      blocks.push({ type: "h", lines: [heading[2]!], level: heading[1]!.length });
    } else if (bullet) {
      if (!current || current.type !== "ul") {
        push();
        current = { type: "ul", lines: [] };
      }
      current.lines.push(bullet[2]!);
    } else if (ordered) {
      if (!current || current.type !== "ol") {
        push();
        current = { type: "ol", lines: [] };
      }
      current.lines.push(ordered[2]!);
    } else if (quote) {
      if (!current || current.type !== "quote") {
        push();
        current = { type: "quote", lines: [] };
      }
      current.lines.push(quote[1]!);
    } else {
      if (!current || current.type !== "p") {
        push();
        current = { type: "p", lines: [] };
      }
      current.lines.push(line);
    }
  }
  push();
  return blocks;
}

export function Markdown({ content, className }: { content: string; className?: string }) {
  const blocks = parseBlocks(content);

  return (
    <div className={classNames("space-y-2 text-sm leading-relaxed", className)}>
      {blocks.map((block, bi) => {
        const key = `b${bi}`;
        if (block.type === "code") {
          return (
            <pre
              key={key}
              className="overflow-x-auto rounded-lg bg-ink-900/80 p-3 font-mono text-[12px] leading-relaxed text-ink-200 ring-1 ring-ink-700/50"
            >
              {block.lang && (
                <div className="mb-1 text-[10px] uppercase tracking-wider text-ink-500">{block.lang}</div>
              )}
              <code>{block.lines.join("\n")}</code>
            </pre>
          );
        }
        if (block.type === "h") {
          const size = block.level === 1 ? "text-base" : block.level === 2 ? "text-sm" : "text-[13px]";
          return (
            <p key={key} className={classNames("font-semibold text-ink-100", size)}>
              {renderInline(block.lines[0]!, key)}
            </p>
          );
        }
        if (block.type === "ul" || block.type === "ol") {
          const ListTag = block.type === "ul" ? "ul" : "ol";
          return (
            <ListTag
              key={key}
              className={classNames(
                "space-y-1 pl-5",
                block.type === "ul" ? "list-disc marker:text-cyber-400" : "list-decimal marker:text-cyber-400",
              )}
            >
              {block.lines.map((item, li) => (
                <li key={`${key}-${li}`}>{renderInline(item, `${key}-${li}`)}</li>
              ))}
            </ListTag>
          );
        }
        if (block.type === "quote") {
          return (
            <blockquote key={key} className="border-l-2 border-cyber-500/40 pl-3 text-ink-300 italic">
              {block.lines.map((l, li) => (
                <Fragment key={`${key}-${li}`}>{renderInline(l, `${key}-${li}`)} </Fragment>
              ))}
            </blockquote>
          );
        }
        return (
          <p key={key} className="whitespace-pre-wrap">
            {block.lines.map((l, li) => (
              <Fragment key={`${key}-${li}`}>
                {li > 0 && <br />}
                {renderInline(l, `${key}-${li}`)}
              </Fragment>
            ))}
          </p>
        );
      })}
    </div>
  );
}
