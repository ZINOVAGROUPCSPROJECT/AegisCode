import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { z } from "zod";
import { AEGIS_ACTIONS, MAX_AI_INPUT_CHARS, MAX_AI_MESSAGES, type Json } from "./ai.contract";

const aegisSchema = z.object({
  action: z.enum(AEGIS_ACTIONS),
  userContent: z.string().min(1).max(MAX_AI_INPUT_CHARS).optional(),
  messages: z
    .array(
      z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string().min(1).max(MAX_AI_INPUT_CHARS),
      }),
    )
    .max(MAX_AI_MESSAGES)
    .optional(),
});

export type AegisAIResponse =
  | { ok: true; action: string; model: string; result: Json }
  | { ok: false; error: string; status: number; retryable: boolean };

/**
 * Authenticated RPC boundary for every AI action. Provider keys, prompts and
 * gateway wiring stay on the server; the browser only ever sees this envelope.
 */
export const aegisAI = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((data: unknown) => aegisSchema.parse(data))
  .handler(async ({ data }): Promise<AegisAIResponse> => {
    const { runAegisAI, AegisAIError } = await import("./ai.server");
    try {
      if (!data.userContent && !data.messages?.length) {
        return {
          ok: false,
          error: "Provide either a prompt or a conversation.",
          status: 400,
          retryable: false,
        };
      }

      const envelope = await runAegisAI({
        action: data.action,
        ...(data.userContent ? { userContent: data.userContent } : {}),
        ...(data.messages?.length ? { messages: data.messages } : {}),
      });

      return {
        ok: true,
        action: envelope.action,
        model: envelope.model,
        result: envelope.result as Json,
      };
    } catch (error) {
      if (error instanceof AegisAIError) {
        return { ok: false, error: error.message, status: error.status, retryable: error.retryable };
      }
      console.error("[AegisCode AI]", error);
      return {
        ok: false,
        error: error instanceof Error ? error.message : "The AI request failed.",
        status: 500,
        retryable: false,
      };
    }
  });
