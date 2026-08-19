import { useState } from "react";
import { Save, Check, Loader2 } from "lucide-react";
import { Button } from "@/components/ui-kit";
import { saveAnalysisReport, type AnalysisKind } from "@/lib/reports";

/**
 * Drop-in action that persists any analysis result into the Reports page.
 */
export function SaveAnalysisButton({
  kind,
  data,
  title,
  scanIds,
  summary,
}: {
  kind: AnalysisKind;
  data: unknown;
  title?: string;
  scanIds?: string[];
  summary?: Record<string, unknown>;
}) {
  const [state, setState] = useState<"idle" | "saving" | "saved">("idle");
  const [error, setError] = useState<string | null>(null);

  const disabled = data === null || data === undefined || state === "saving";

  const save = async () => {
    setState("saving");
    setError(null);
    try {
      await saveAnalysisReport({
        kind,
        data,
        ...(title ? { title } : {}),
        ...(scanIds ? { scanIds } : {}),
        ...(summary ? { summary } : {}),
      });
      setState("saved");
      window.setTimeout(() => setState("idle"), 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("idle");
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <Button size="sm" variant="ghost" onClick={save} disabled={disabled}>
        <span className="flex items-center gap-1.5">
          {state === "saving" ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : state === "saved" ? (
            <Check className="h-3.5 w-3.5 text-volt-300" />
          ) : (
            <Save className="h-3.5 w-3.5" />
          )}
          {state === "saved" ? "Saved to Reports" : "Save to Reports"}
        </span>
      </Button>
      {error && <span className="text-[11px] text-danger">{error}</span>}
    </div>
  );
}