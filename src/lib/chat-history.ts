import { supabase } from "@/lib/db";

export interface StoredChatMessage {
  role: "user" | "assistant";
  content: string;
}

/**
 * Chat history is stored per user in Lovable Cloud (RLS-scoped) instead of
 * localStorage, so a conversation survives reloads, navigation and switching
 * devices, and can never "disappear" when browser storage is cleared.
 */
export async function getOrCreateSession(): Promise<string | null> {
  const { data: auth } = await supabase.auth.getUser();
  if (!auth.user) return null;

  const { data: existing, error } = await supabase
    .from("ai_chat_sessions")
    .select("id")
    .order("updated_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw error;
  if (existing) return existing.id;

  const { data: created, error: createError } = await supabase
    .from("ai_chat_sessions")
    .insert({ user_id: auth.user.id, title: "Assistant" })
    .select("id")
    .single();

  if (createError) throw createError;
  return created.id;
}

export async function loadMessages(sessionId: string): Promise<StoredChatMessage[]> {
  const { data, error } = await supabase
    .from("ai_chat_messages")
    .select("role, content")
    .eq("session_id", sessionId)
    .order("created_at", { ascending: true })
    .limit(400);

  if (error) throw error;
  return (data ?? [])
    .filter((row): row is { role: string; content: string } => Boolean(row.content))
    .map((row) => ({
      role: row.role === "assistant" ? "assistant" : "user",
      content: row.content,
    }));
}

export async function appendMessage(
  sessionId: string,
  message: StoredChatMessage,
  page: string,
): Promise<void> {
  const { data: auth } = await supabase.auth.getUser();
  if (!auth.user) return;

  const { error } = await supabase.from("ai_chat_messages").insert({
    session_id: sessionId,
    user_id: auth.user.id,
    role: message.role,
    content: message.content,
    page,
  });
  if (error) throw error;

  await supabase
    .from("ai_chat_sessions")
    .update({ updated_at: new Date().toISOString() })
    .eq("id", sessionId);
}

export async function clearSession(sessionId: string): Promise<void> {
  const { error } = await supabase.from("ai_chat_messages").delete().eq("session_id", sessionId);
  if (error) throw error;
}
