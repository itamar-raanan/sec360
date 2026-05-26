# Design

## Theme

Dark. Background: `oklch(8% 0.01 280)` (~`#0a0a0f`). The interface is calibrated for dim environments. Light mode is not offered.

## Color

Strategy: **Restrained** — tinted neutrals with violet as the single accent.

| Role | Token / Value | Notes |
|---|---|---|
| Base surface | `gray-950` / `#0a0a0f` | Page background |
| Card surface | `gray-900` | Panels, cards |
| Elevated | `gray-800` | Inputs, hover states, table headers |
| Border | `gray-800` / `white/[0.06]` | Subtle; sidebar uses lower-opacity white |
| Accent | `violet-600` / `#7c3aed` | Primary actions, active nav, brand mark |
| Accent muted | `violet-500/20`, `violet-400` | Badges, indicators |
| Risk: low | `green-400` + `green-500/15` bg | |
| Risk: medium | `yellow-400` + `yellow-500/15` bg | |
| Risk: high | `orange-400` + `orange-500/15` bg | |
| Risk: critical | `red-400` + `red-500/15` bg | |
| Status: compliant | `green-400` | |
| Status: partial | `yellow-400` | |
| Status: non-compliant | `red-400` | |
| Text primary | `white` | |
| Text secondary | `gray-300` | Body, table cells |
| Text tertiary | `gray-400`–`gray-500` | Labels, metadata |
| Text disabled | `gray-600` | |

**Anti-pattern**: blue (`blue-600`, `blue-400`) is used inconsistently in the codebase for pagination active state and focus rings. It should be replaced with violet to match the accent system.

## Typography

Font: system stack — `-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif`.

| Role | Size | Weight | Color |
|---|---|---|---|
| Page heading | `text-xl` / 20px | `font-bold` | `white` |
| Section heading | `text-sm` / 14px | `font-semibold` | `white` |
| Label / nav | `text-sm` / 14px | `font-medium` | `gray-400`–`gray-200` |
| Body / table | `text-sm` / 14px | `font-normal` | `gray-300` |
| Caption / metadata | `text-xs` / 12px | `font-normal` | `gray-500` |
| Stat value | `text-3xl` / 30px | `font-bold` | `white` |

Capitalization: UI labels use Sentence case. Table column headers use UPPERCASE with `tracking-wider`.

## Spacing

Tailwind scale. Key values in use:
- Card padding: `p-5` (20px)
- Section gap: `gap-4` or `gap-5` (16–20px)
- Table cell: `px-4 py-3`
- Nav item: `px-3 py-2.5`
- Icon button: `p-1`–`p-2`

## Components

**StatCard**: `bg-gray-900 border border-gray-800 rounded-xl p-5`. Clickable variant adds `pressable` class. Always has: title (gray-400), icon (colored), value (white, 3xl bold), optional subtitle (gray-500).

**DataTable**: Rounded container with `border-gray-800`. Header: `bg-gray-900/50`, uppercase, `text-gray-400`. Rows: `hover:bg-gray-800/40`, `border-b border-gray-800/50`. Stagger animation on row entry.

**RiskBadge**: Pill with transparent background tint + colored border + colored text. Four levels: low/medium/high/critical.

**StatusBadge**: Same pill pattern. States: compliant/partial/non-compliant/active/inactive/offboarded.

**SearchBar**: `bg-gray-800 border border-gray-700 rounded-lg`. Focus: `border-violet-500 ring-1 ring-violet-500`.

**Buttons (primary)**: `bg-violet-600 hover:bg-violet-500 text-white rounded-lg`. Add `pressable` class.

**Buttons (secondary/ghost)**: `bg-gray-800 border border-gray-700 hover:bg-gray-700 text-gray-300 rounded-lg`. Add `pressable` class.

## Motion

Custom easing: `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)`.
- UI transitions: 150ms
- Entry animations (`animate-fade-up`): 280ms
- Row stagger: 30ms per item
- Press feedback (`pressable`): 160ms, `scale(0.97)`
- Respects `prefers-reduced-motion`.

## Focus

Focus ring: `outline-none focus-visible:ring-2 focus-visible:ring-violet-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950`. Violet matches the accent, offset against the dark base.
