# Design

## Theme

Dark by default, with a fully supported light theme. The dark interface is calibrated for dim operations environments; the light theme uses cool neutral surfaces and higher-contrast semantic colors.

## Color

Strategy: **Restrained** — cool tinted neutrals with emerald as the single interaction accent. Risk and health colors remain semantic and must not be used decoratively.

| Role | Token / Value | Notes |
|---|---|---|
| Base surface | `gray-950` / `#0a0a0f` | Page background |
| Card surface | `gray-900` | Panels, cards |
| Elevated | `gray-800` | Inputs, hover states, table headers |
| Border | `gray-800` / `white/[0.06]` | Subtle; sidebar uses lower-opacity white |
| Accent | `emerald-600` / `#087a5b` | Primary actions, active nav, brand mark |
| Accent muted | `emerald-500/12`, `emerald-400` | Selected filters and interaction feedback |
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

**Anti-pattern**: do not use emerald as decoration. It means action, healthy state, or active selection. Product colors may appear only in compact badges or icons.

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

**SearchBar**: inset semantic surface with the emerald focus ring.

**Buttons (primary)**: semantic `ui-primary-button` using the emerald accent, an inner highlight, and restrained pressed feedback.

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
