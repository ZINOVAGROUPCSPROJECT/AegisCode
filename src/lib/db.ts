/**
 * AegisCode data client.
 *
 * The generated client is strongly typed against the database, but AegisCode
 * stores rich JSON documents (evidence chains, attack paths, SBOM entries) that
 * the app models with its own domain interfaces in `@/lib/types`. This module
 * exposes the same runtime client with loose row typing so pages can map rows
 * onto those domain interfaces.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { supabase as generatedClient } from "@/integrations/supabase/client";

export const supabase = generatedClient as unknown as SupabaseClient;
