import "@testing-library/jest-dom/vitest";

if (typeof crypto.randomUUID !== "function") {
  Object.defineProperty(crypto, "randomUUID", { value: () => "00000000-0000-4000-8000-000000000001" });
}
