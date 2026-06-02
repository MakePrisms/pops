import type { ReactNode } from "react";

export const metadata = {
  title: "pops gating demo",
  description: "402 -> verify + NUT-03 swap (WASM, Node runtime) -> 200",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
