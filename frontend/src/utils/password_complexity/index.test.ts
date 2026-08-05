// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { TFunction } from "i18next";
import { describe, expect, it } from "vitest";

import { estimatePasswordComplexity } from "./index";

// Fake translator that echoes the key back, so we can assert which
// warning/suggestion strings the estimator produced.
const t = ((key: string) => key) as unknown as TFunction;

describe("estimatePasswordComplexity()", () => {
  it("scores a strong password highly", async () => {
    const result = await estimatePasswordComplexity(
      "correcthorsebatterystaple",
      t,
    );
    expect(result.score).toBeGreaterThanOrEqual(3);
  });

  it("scores a common password as the weakest", async () => {
    const result = await estimatePasswordComplexity("password", t);
    expect(result.score).toBe(0);
  });

  it("flags a repeated password", async () => {
    const result = await estimatePasswordComplexity("aaaaaa", t);
    expect(result.score).toBe(0);
    expect(result.improvementsText).toContain(
      "frontend.password_strength.warning.simple_repeat",
    );
  });

  // Regression test for the keyboard adjacency graphs being misloaded.
  it("detects keyboard-walk patterns via the adjacency graphs", async () => {
    const result = await estimatePasswordComplexity("fdsapoiuytr", t);
    expect(result.improvementsText).toContain(
      "frontend.password_strength.warning.straight_row",
    );
    expect(result.improvementsText).toContain(
      "frontend.password_strength.suggestion.longer_keyboard_pattern",
    );
  });

  it("always returns localised score text", async () => {
    const result = await estimatePasswordComplexity("password", t);
    expect(result.scoreText).toBe("frontend.password_strength.score.0");
  });
});
