import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { scanRepository, analyzeDependencies } from "./engines/scan.server";
import { runRealDast } from "./engines/dast.server";

const repoSchema = z.object({
  repo: z.string().min(3),
  provider: z.enum(["github", "gitlab"]).optional(),
  ref: z.string().optional(),
  token: z.string().optional(),
});

export const scanRepositoryFn = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => repoSchema.parse(data))
  .handler(async ({ data }) =>
    scanRepository({
      repo: data.repo,
      provider: data.provider,
      ref: data.ref,
      token: data.token,
    }),
  );

const scaSchema = z.object({
  manifests: z.array(z.object({ path: z.string(), content: z.string() })).min(1),
});

export const analyzeDependenciesFn = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => scaSchema.parse(data))
  .handler(async ({ data }) => analyzeDependencies({ manifests: data.manifests }));

const dastSchema = z.object({
  target: z.string().min(4),
  authorized: z.boolean(),
});

export const dastScanFn = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => dastSchema.parse(data))
  .handler(async ({ data }) => runRealDast(data.target, data.authorized));
