# Short Circuit Design Specification

Version: 1.0

---

# Purpose

This document is the **single source of truth** for all user interface, product, and web design across Short Circuit.

Every interface, page, application, dashboard, landing page, prototype, marketing asset, and future product must follow these specifications unless an exception is explicitly documented.

When a design decision is ambiguous, always choose the option that best aligns with the philosophy defined in this document.

Consistency is valued more than originality.

---

# AI Instructions

When using this document with AI design tools (Stitch, Lovable, Cursor, Claude, ChatGPT, etc.), these instructions take precedence over default design behaviors.

The AI must:

- Follow this specification exactly.
- Never introduce colors outside the defined palette.
- Never change typography unless explicitly instructed.
- Never invent additional visual styles.
- Preserve visual consistency over novelty.
- Prefer whitespace over decoration.
- Favor typography over graphics.
- Prefer structure over effects.
- Design like an engineering company, not a marketing agency.
- Use minimal motion.
- Keep layouts clean, modular, and predictable.
- Every design should feel like it belongs to the same ecosystem.

If multiple valid solutions exist, choose the simplest one.

---

# Brand Philosophy

Short Circuit is an engineering company.

Our visual identity should communicate precision, confidence, technical excellence, and deliberate craftsmanship.

Nothing exists purely for decoration.

Every element has a purpose.

Typography communicates hierarchy.

Spacing communicates organization.

Color communicates meaning.

Motion communicates interaction.

The interface should disappear behind the user's work.

We do not chase trends.

We create timeless products.

---

# Design Principles

Every design decision should satisfy the following principles.

## Function Before Decoration

Visual elements exist to improve understanding.

Do not add gradients, illustrations, shadows, icons, or colors unless they improve usability or communication.

---

## Typography Creates Hierarchy

Typography is the primary communication tool.

Large type creates importance.

Small type provides detail.

Never rely on color alone to establish hierarchy.

---

## Space Creates Structure

Whitespace is not empty.

Whitespace separates ideas.

Increase spacing before adding borders.

Increase spacing before adding background colors.

Increase spacing before adding visual decoration.

---

## Color Has Meaning

Color should communicate state, priority, or interaction.

Avoid decorative color usage.

Every colored element should have a reason to exist.

---

## Consistency Creates Trust

Every button should behave the same.

Every card should feel the same.

Every navigation should follow identical rules.

Interfaces should feel predictable.

---

## Simplicity Wins

When choosing between two solutions:

Choose the simpler one.

If removing something does not reduce usability:

Remove it.

---

# Brand Personality

Every interface should feel:

- Technical
- Industrial
- Professional
- Confident
- Structured
- Editorial
- Modern
- Purposeful
- Quiet
- Premium

Never feel:

- Cute
- Playful
- Cartoonish
- Flashy
- Futuristic for the sake of it
- Corporate template
- Startup cliché
- Gaming UI

---

# Emotional Goals

Users should feel:

"I trust this product."

"This company knows what they're doing."

"This interface stays out of my way."

"This feels engineered."

Never make users feel overwhelmed.

Never try to impress through excessive visuals.

Confidence comes from restraint.

---

# Visual Identity

The visual identity is built around five ideas.

## Typography

Typography is the hero.

Large headlines.

Strong hierarchy.

Minimal distractions.

---

## Contrast

High contrast improves readability.

Dark backgrounds.

Bright typography.

Subtle borders.

Purposeful emphasis.

---

## Structure

Every element aligns to a grid.

Nothing floats randomly.

Spacing should feel mathematical.

---

## Rhythm

The interface should have a consistent vertical rhythm.

Users should naturally understand where sections begin and end.

---

## Precision

Every corner radius.

Every spacing value.

Every animation.

Every border.

Every font size.

Should be intentional.

---

# Color System

The palette is intentionally limited.

A limited palette creates recognition.

Never expand the palette without updating this specification.

---

## Core Colors

### Black

Primary background.

#000000

---

### Surface

Cards

Panels

Dialogs

Menus

#111111

---

### Elevated Surface

Hover states

Secondary panels

Nested cards

#181818

---

### Border

#2B2B2B

Borders should remain subtle.

---

### White

Primary text.

#FFFFFF

---

### Muted Text

#B8B8B8

---

### Disabled Text

#7A7A7A

---

### Brand Red

Primary Accent

#EB1B26

The brand red is reserved for:

Primary actions

Active navigation

Interactive links

Important metrics

Critical information

Brand marks

Never use it as a large background color.

Never flood an interface with red.

---

### Dark Red

Hover

Pressed

Highlights

#A80F18

---

## Color Rules

One accent color.

Never introduce blue.

Never introduce green unless representing success.

Never introduce yellow unless representing warning.

Never introduce additional branding colors.

The interface should remain approximately:

85% black

10% white

5% accent

---

# Semantic Colors

These colors exist for communication.

They should never replace the brand accent.

Success

#1FA971

Warning

#F4B740

Danger

Uses Brand Red

Information

White

---

# Color Usage Rules

Primary buttons

Brand Red

---

Secondary buttons

Transparent

White text

Border only

---

Cards

Dark surface

---

Navigation

Dark background

Active item

Brand Red

---

Links

Brand Red

Underline on hover.

---

Charts

Neutral grayscale.

One highlighted data series may use Brand Red.

---

# Typography

Typography is the strongest visual element of the brand.

Large typography communicates confidence.

Avoid decorative type treatments.

---

## Font Families

Primary Display

Anton

Purpose:

Large headlines

Section titles

Marketing

Landing pages

Hero sections

Always uppercase.

Never italic.

Never stretched.

Never outlined.

---

Primary Interface

Poppins

Purpose:

Body

Forms

Navigation

Buttons

Documentation

Tables

---

Arabic

IBM Plex Sans Arabic

Used wherever Arabic content exists.

Maintain identical hierarchy.

---

Monospace

JetBrains Mono

Purpose:

Code

Terminal

IDs

Technical information

Never use monospace for body copy.

---

# Typography Scale

Display XXL

80px

Display XL

64px

Display L

48px

Display M

40px

Heading XL

32px

Heading L

28px

Heading M

24px

Heading S

20px

Body Large

18px

Body

16px

Body Small

14px

Caption

12px

Overline

11px

---

# Font Weights

Anton

Regular only

Poppins

300

400

500

600

IBM Plex Arabic

400

500

600

Avoid excessive bold usage.

Hierarchy should come from size before weight.

---

# Line Heights

Display

1.0

Heading

1.2

Body

1.6

Caption

1.5

---

# Letter Spacing

Large Headlines

-2%

Section Labels

+10%

Body

Normal

Buttons

+2%

Navigation

+3%

---

# Text Alignment

Default:

Left aligned.

Never center large blocks of text.

Centered layouts should only be used for:

Hero sections

404 pages

Authentication

Landing page call-to-actions

Everything else should align to the grid.

---

# Iconography

Icons support text.

Icons never replace text.

Preferred libraries:

- Phosphor
- Lucide

Use outlined icons only.

Filled icons should be avoided unless representing active states.

Default sizes:

16px

20px

24px

32px

Icons should always align with surrounding typography.

Never decorate interfaces with random icons.

---

# Spacing System

Spacing follows an 8-point grid.

Allowed spacing values:

4

8

12

16

24

32

40

48

64

80

96

128

160

Never invent arbitrary spacing values.

Spacing should remain consistent across all products.

Whitespace should solve layout problems before borders or colors are introduced.

---

# Layout System

The layout system establishes visual rhythm, predictability, and clarity across every Short Circuit product.

Users should never wonder where content begins, where actions belong, or how information is organized.

Every page should feel engineered rather than decorated.

---

## Containers

Use centered containers for nearly every page.

Maximum widths:

XS: 480px

SM: 640px

MD: 768px

LG: 1024px

XL: 1280px

XXL: 1440px

Application dashboards should primarily use the XL container.

Documentation pages may use 960px reading width.

Landing pages may use XXL containers.

Never stretch body content across the full screen.

---

## Page Padding

Desktop

48px

Tablet

32px

Mobile

24px

Small Mobile

16px

Never allow content to touch screen edges.

---

## Reading Width

Body copy should remain comfortable to read.

Maximum paragraph width:

720px

Avoid long lines of text.

---

## Vertical Rhythm

Every page should follow a consistent vertical rhythm.

Typical spacing:

Hero → 160px

Section → 96px

Subsection → 64px

Card Groups → 32px

Related Elements → 16px

Labels → 8px

Maintain rhythm throughout the interface.

---

# Grid System

Every interface should align to a predictable grid.

Nothing should feel randomly positioned.

---

## Desktop

12 Columns

Column Gap

24px

Outer Margin

48px

---

## Tablet

8 Columns

Gap

24px

Outer Margin

32px

---

## Mobile

4 Columns

Gap

16px

Outer Margin

16px

---

## Alignment Rules

Always align:

Cards

Buttons

Titles

Images

Tables

Forms

Icons

Avoid visual drift.

If two components appear related, align them.

---

# Layout Hierarchy

Each page should follow this hierarchy.

1.

Page Identifier

Small uppercase label.

Accent color.

Example

PROJECT

GUIDELINES

ENGINE

---

2.

Primary Heading

Largest typography on page.

Only one dominant heading.

---

3.

Supporting Description

Body text.

Muted color.

Maximum two paragraphs.

---

4.

Primary Actions

Buttons.

Search.

Filters.

---

5.

Content

Cards

Tables

Charts

Documentation

Forms

---

# Section Composition

Every section should contain:

Optional Label

↓

Large Heading

↓

Description

↓

Content

↓

Whitespace

↓

Next Section

Avoid stacking unrelated components.

---

# Card System

Cards are organizational containers.

They do not exist for decoration.

Cards should establish grouping.

Not emphasis.

---

## Card Background

Surface

#111111

---

## Border

1px

Subtle.

#2B2B2B

---

## Radius

12px

Never exceed 16px.

---

## Padding

Small

16px

Medium

24px

Large

32px

Hero

48px

---

## Card Types

Information Card

Metric Card

Documentation Card

Feature Card

Settings Card

Interactive Card

Data Card

Avoid unnecessary variations.

---

## Card Hover

Increase border contrast.

Increase elevation slightly.

Do not scale cards.

Do not rotate.

Do not animate excessively.

---

# Borders

Borders organize.

Borders never decorate.

---

## Border Width

Default

1px

Strong

2px

Never exceed 2px.

---

## Border Color

Default

#2B2B2B

Hover

#3A3A3A

Focus

Brand Red

---

# Corner Radius

Radius should remain subtle.

Small

8px

Default

12px

Large

16px

Circular

999px

Reserved only for avatars.

Avoid pill buttons.

---

# Elevation

Depth should come from contrast.

Not shadows.

---

Elevation 0

Flat

---

Elevation 1

Small shadow

0 2px 8px rgba(0,0,0,.15)

---

Elevation 2

0 8px 24px rgba(0,0,0,.18)

---

Elevation 3

0 16px 48px rgba(0,0,0,.22)

Only dialogs and overlays should reach Level 3.

---

# Motion

Motion reinforces interaction.

Motion should never distract.

Every animation should communicate intent.

---

## Principles

Fast.

Smooth.

Subtle.

Predictable.

---

## Durations

Instant

0ms

Fast

120ms

Default

180ms

Slow

250ms

Maximum

300ms

Never exceed 300ms.

---

## Timing Function

Default

ease-out

Entrance

ease-out

Exit

ease-in

Avoid:

Bounce

Elastic

Spring

Overshoot

---

## Hover Motion

Opacity

Border

Background

Small translation

Maximum

2px

Avoid scaling above 1.02.

---

## Button Motion

Hover

Background transition

↓

Border transition

↓

Text transition

↓

Shadow (optional)

---

## Card Motion

Hover

Border brightens.

Shadow increases slightly.

No scaling.

No floating.

---

## Modal Motion

Fade

↓

Translate Y

8px

Duration

180ms

Exit reverses animation.

---

## Drawer Motion

Slide

240ms

No bounce.

---

## Tooltip Motion

Fade only.

120ms.

---

## Navigation Motion

Underline expands.

Background fades.

Text color changes.

Never slide menus dramatically.

---

## Loading

Prefer skeleton loaders.

Avoid spinning indicators whenever possible.

Skeletons should pulse subtly.

---

# Accessibility

Accessibility is mandatory.

Every interface must be usable without a mouse.

---

## Contrast

Minimum

4.5:1

Large Text

3:1

Primary actions should exceed minimum requirements.

---

## Focus

Every interactive component must have visible focus.

Focus color:

Brand Red

Never remove focus outlines.

---

## Keyboard Navigation

Everything interactive must support:

Tab

Shift+Tab

Enter

Space

Escape

Arrow Keys where appropriate.

---

## Screen Readers

Every control requires:

Accessible label

Role

State

Description when necessary.

Icons alone should never communicate meaning.

---

## Motion Accessibility

Respect reduced motion preferences.

Disable:

Large transitions

Parallax

Animated entrances

Continuous animations

---

## Touch Targets

Minimum

44px × 44px

Even if the visual element appears smaller.

---

## Forms

Every input requires:

Visible label

Helper text when appropriate

Clear validation message

Error state

Success state

Never rely on color alone.

---

# Responsive Design

Responsive design is adaptation.

Not shrinking.

---

## Breakpoints

XS

0–479

SM

480–767

MD

768–1023

LG

1024–1279

XL

1280–1439

XXL

1440+

---

## Mobile Philosophy

Content first.

Actions second.

Decoration last.

---

## Navigation

Desktop

Horizontal

Tablet

Condensed

Mobile

Drawer

---

## Typography Scaling

Display sizes reduce proportionally.

Body text remains between:

16–18px

Never use body text below 16px.

---

## Cards

Desktop

Multiple columns

Tablet

Two columns

Mobile

Single column

---

## Tables

Desktop

Full table

Tablet

Horizontal scrolling allowed

Mobile

Transform into stacked data cards where practical

---

## Forms

Desktop

Two-column layouts when appropriate

Mobile

Single column only

---

# Design Rhythm

Every page should feel balanced.

Follow this visual cadence:

Whitespace

↓

Heading

↓

Description

↓

Primary Action

↓

Content

↓

Whitespace

Repeat consistently.

Never allow layouts to feel crowded.

---

# Visual Consistency Rules

Always prioritize:

Alignment over decoration.

Typography over illustration.

Whitespace over borders.

Contrast over color.

Structure over animation.

Consistency over creativity.

The user should recognize a Short Circuit interface instantly, regardless of the product.

---

# Component System

Components are the building blocks of every Short Circuit product.

Every component should feel like it belongs to the same ecosystem.

Components should be:

- Predictable
- Minimal
- Accessible
- Modular
- Consistent
- Engineering-first

Never design components in isolation.

Each component should inherit the visual language defined by this document.

---

# Interaction States

Every interactive component must define all interaction states.

Required states:

Default

Hover

Focus

Pressed

Disabled

Loading (when applicable)

Error (when applicable)

Success (when applicable)

No component should invent additional states.

---

# Buttons

Buttons represent intentional actions.

There should always be one obvious primary action.

Avoid placing multiple primary buttons beside one another.

---

## Button Hierarchy

Primary

Secondary

Ghost

Danger

Icon

Link

---

## Primary Button

Purpose

The single most important action within a section.

Examples

Create Project

Generate Scene

Export

Deploy

Analyze

---

Appearance

Background

Brand Red

Text

White

Border

None

Radius

12px

Height

48px

Horizontal Padding

24px

Font

Poppins

Medium

16px

---

Hover

Background

Dark Red

Shadow

Elevation Level 1

Cursor

Pointer

Transition

180ms

---

Pressed

Background darkens.

Shadow removed.

---

Disabled

Background

#2B2B2B

Text

#7A7A7A

Cursor

Not Allowed

Never reduce opacity below 70%.

---

Loading

Replace text with spinner.

Keep width fixed.

Never resize buttons while loading.

---

## Secondary Button

Purpose

Alternative actions.

Appearance

Transparent

Border

1px

#3A3A3A

Text

White

---

Hover

Border

Brand Red

Text

Brand Red

Background

rgba(235,27,38,.05)

---

Pressed

Background slightly darkens.

---

## Ghost Button

No border.

No background.

White text.

Hover

Background

rgba(255,255,255,.05)

---

## Danger Button

Reserved for destructive actions.

Delete

Remove

Archive

Reset

Background

Brand Red

Hover

Dark Red

Confirmation should always be required.

---

## Icon Buttons

Size

40px

Square

Centered

Never smaller than 40px.

Icons

20px

Outlined

No filled icons unless active.

---

## Button Rules

Only one primary button per logical section.

Never use icon-only buttons for destructive actions.

Never mix multiple accent colors.

Buttons should never use gradients.

Buttons should never have excessive shadows.

---

# Links

Links indicate navigation.

They are not buttons.

---

Appearance

Color

Brand Red

Underline

On Hover

Visited links remain unchanged.

---

External Links

Display external icon.

Open in new tab when appropriate.

---

# Forms

Forms should feel structured and calm.

Reduce cognitive load.

Group related inputs.

Avoid unnecessarily long forms.

---

# Labels

Always visible.

Never rely solely on placeholders.

Labels sit above inputs.

Spacing

8px

---

# Helper Text

Placed below input.

Muted text color.

Maximum two lines.

---

# Validation

Validation appears below helper text.

Error

Brand Red

Success

Success Green

Messages should explain the problem.

Bad

Invalid Input

Good

Email address is required.

---

# Inputs

Height

48px

Radius

12px

Background

#111111

Border

#2B2B2B

Text

White

Placeholder

#7A7A7A

---

Hover

Border

#444444

---

Focus

Border

Brand Red

Outline

2px Brand Red with subtle transparency

Never rely solely on browser focus styles.

---

Disabled

Background

#0D0D0D

Border

#1E1E1E

Text

#666666

---

# Text Areas

Minimum Height

140px

Resizable

Vertical Only

Padding

16px

Character Counter

Optional

Bottom Right

---

# Select

Uses identical styling to text input.

Dropdown

Dark Surface

Border

#2B2B2B

Selected option

Brand Red

Hover

Dark Surface

---

# Checkboxes

Size

20px

Border

2px

Default

Gray

Checked

Brand Red

Animated

120ms

Never use platform-native styling.

---

# Radio Buttons

Size

20px

Border

2px

Selected

Filled Brand Red

Animation

120ms

---

# Switches

Width

44px

Height

24px

Track

Dark Gray

Thumb

White

Active Track

Brand Red

Animation

180ms

---

# Search

Search is a primary workflow.

Search bars should be visually prominent.

Include:

Search Icon

Placeholder

Clear Button

Keyboard Shortcut (when applicable)

Example Placeholder

Search projects...

Search scenes...

Search documentation...

Avoid generic placeholders like

Search...

---

# Input Groups

Icons

Prefix

Suffix

Units

Buttons

Should all align perfectly.

Maintain

16px

internal spacing.

---

# Cards

Cards organize information.

They should never feel decorative.

---

## Information Card

Purpose

Display related content.

Padding

24px

Border

1px

Radius

12px

---

## Metric Card

Large Metric

32px

Supporting Label

14px

Trend Indicator

Optional

Accent color reserved for meaningful changes.

---

## Interactive Card

Entire card clickable.

Hover

Border brightens.

Shadow increases.

Cursor

Pointer

Never scale.

---

## Documentation Card

Optimized for long-form text.

Reading width

720px

Padding

32px

Typography spacing increased.

---

## Empty Card

Center content.

Icon

Heading

Description

Action

Generous whitespace.

---

# Dividers

Purpose

Separate unrelated content.

Color

#2B2B2B

Thickness

1px

Spacing

24px

Avoid excessive divider usage.

Whitespace is usually preferable.

---

# Badges

Used for metadata.

Never use badges as buttons.

---

Sizes

Small

Medium

Large

---

Variants

Neutral

Success

Warning

Danger

Information

---

Neutral

Dark Surface

White Text

Border

Gray

---

Success

Dark Surface

Green Text

---

Warning

Dark Surface

Yellow Text

---

Danger

Dark Surface

Red Text

---

# Alerts

Alerts communicate important information.

Not every message deserves an alert.

---

Variants

Information

Success

Warning

Danger

---

Structure

Icon

Heading

Description

Optional Action

---

Background

Dark Surface

Left Border

Semantic Color

Padding

20px

Radius

12px

---

# Toast Notifications

Purpose

Temporary feedback.

Location

Bottom Right

Desktop

Bottom Center

Mobile

---

Duration

4 Seconds

Closable

Yes

---

Animations

Fade

Translate Up

180ms

---

Avoid stacking more than three simultaneously.

---

# Progress Indicators

Linear

Circular

Step

Use Brand Red for active progress.

Background Track

#2B2B2B

---

# Skeleton Loaders

Always prefer skeletons over spinners.

Animate opacity only.

Duration

1.5 seconds

Infinite

Do not shimmer aggressively.

---

# Tooltips

Purpose

Clarify.

Never explain obvious UI.

Maximum width

280px

Padding

12px

Background

#181818

Border

#2B2B2B

Text

14px

Fade

120ms

---

# Dropdown Menus

Background

#111111

Border

#2B2B2B

Radius

12px

Padding

8px

Item Height

40px

Hover

Subtle gray background

Active

Brand Red text

Never animate dropdown items individually.

---

# Design Consistency Rules

Every component should:

• Align to the spacing system.

• Use approved typography.

• Use approved colors.

• Use approved motion.

• Support keyboard interaction.

• Support screen readers.

• Maintain consistent padding.

• Maintain consistent radius.

• Never introduce visual surprises.

When creating new components, inherit existing patterns before inventing new ones.

Short Circuit products should feel like one cohesive system, regardless of which team or product created them.

---

# Navigation System

Navigation should be invisible.

Users should instinctively understand where they are, where they can go, and what actions are available.

Navigation should never compete with content.

---

# Navigation Hierarchy

Every application should expose navigation in the following order:

1. Primary Navigation
2. Current Context
3. Secondary Actions
4. User Actions

Never mix navigation with page actions.

---

# Top Navigation

Preferred for:

- Dashboards
- Documentation
- Marketing Websites
- Admin Panels

Height

72px

Background

Black

Bottom Border

1px #2B2B2B

Padding

48px Desktop

32px Tablet

16px Mobile

---

## Layout

Left

Logo

Center

Primary Navigation

Right

Search

Notifications

Profile

---

Navigation Items

Font

Poppins

Medium

15px

Color

Muted White

Hover

White

Active

Brand Red

Underline

2px

Animated

180ms

---

Never:

Use oversized navigation.

Use filled backgrounds for active items.

Center the logo.

---

# Sidebar Navigation

Use only when applications contain many sections.

Preferred Width

280px

Collapsed

80px

Background

Black

Right Border

1px #2B2B2B

Navigation Items

48px Height

12px Radius

Hover

Dark Surface

Active

Dark Surface

Left Accent Border

4px Brand Red

Never highlight the entire sidebar.

---

# Breadcrumbs

Use only when hierarchy exceeds two levels.

Example

Projects

/

Scene Reconstruction

/

Settings

Current page

White

Previous pages

Muted

Hover

Brand Red

---

# Tabs

Purpose

Switch related content.

Do not use tabs for navigation between unrelated pages.

---

Height

48px

Bottom Border

1px #2B2B2B

Active Tab

White

Bottom Border

Brand Red

Inactive

Muted

Hover

White

Transition

180ms

Never animate content horizontally.

---

# Pagination

Minimal.

Previous

Page Numbers

Next

Current Page

Brand Red

Hover

White

Never use oversized pagination controls.

---

# Tables

Tables should prioritize readability over density.

Every table should feel lightweight.

---

## Table Structure

Header

Body

Optional Footer

---

Header

Height

56px

Background

Dark Surface

Font

Poppins Medium

Uppercase

Letter Spacing

4%

Border Bottom

#2B2B2B

---

Rows

Height

56px Minimum

Hover

Dark Surface

Selected

Subtle Brand Red Background

Border Bottom

#222222

Avoid zebra striping.

---

Text Alignment

Numbers

Right

Text

Left

Status

Center

Actions

Right

---

Sorting

Arrow appears only on hover.

Active sort

Brand Red

---

Empty Tables

Centered Icon

Title

Description

Primary Action

---

# Data Visualization

Charts should communicate information.

Never decoration.

Use neutral colors.

Highlight only meaningful information.

---

## Color Rules

Primary Dataset

White

Secondary Dataset

Gray

Highlight

Brand Red

Grid

#222222

Axis

Muted

Background

Transparent

---

## Line Charts

Line Width

2px

Points

Hidden

Reveal on hover.

---

## Bar Charts

Radius

6px

Spacing

8px

Hover

Brand Red

---

## Pie Charts

Avoid unless necessary.

Maximum

5 Segments

---

## Tooltips

Dark Surface

White Text

Border

#2B2B2B

Metric

Bold

---

# Search Experience

Search should be available globally.

Keyboard Shortcut

⌘K

Ctrl+K

Preferred.

Search should support:

Projects

Documentation

Commands

Files

Users

Settings

Recent Items

---

Search Results

Grouped.

Section Titles

Uppercase

Muted

Hover

Dark Surface

Active

Brand Red

---

# Filters

Filters belong above data.

Never hide important filters.

Spacing

16px

Wrap naturally on mobile.

Selected Filter

Brand Red Border

---

# Modals

Purpose

Focused interaction.

Avoid placing entire workflows inside modals.

---

Sizes

Small

480px

Medium

640px

Large

960px

Fullscreen

Only when necessary.

---

Structure

Header

Content

Footer

---

Header

Title

Close Button

Divider

---

Footer

Primary Action

Secondary Action

Never more than two primary actions.

---

Overlay

rgba(0,0,0,.75)

Blur

Optional

4px

---

Animation

Fade

+

TranslateY 8px

180ms

---

# Drawers

Used for secondary workflows.

Slide from right.

Width

480px

Maximum

40vw

Mobile

Full Width

---

# Empty States

Every empty state should encourage the next action.

Structure

Illustration (optional)

Heading

Description

Primary Action

Secondary Action (optional)

Avoid humor.

Remain professional.

---

Example

No Projects Yet

Create your first project to begin managing your work.

[Create Project]

---

# Error States

Errors should explain:

What happened

Why it happened (if known)

How to recover

Never expose stack traces.

---

Bad

Something went wrong.

Good

Unable to save your project.

Please check your internet connection and try again.

---

# Success States

Success should be subtle.

Avoid celebration animations.

Use:

Check Icon

Title

Optional Description

Fade out automatically when appropriate.

---

# Authentication

Authentication screens should be simple.

Center aligned.

Maximum Width

480px

Logo

↓

Heading

↓

Description

↓

Form

↓

Primary Button

↓

Secondary Links

Avoid unnecessary imagery.

---

# Dashboard Layout

Every dashboard follows:

Header

↓

Toolbar

↓

Filters

↓

Content

↓

Footer (optional)

---

Dashboard Cards

Equal Heights

Consistent Padding

Consistent Radius

No floating widgets.

---

# Settings Pages

Navigation

Left

Content

Right

Group settings into categories.

Each category should begin with:

Title

Description

Content

Divider

---

# Documentation Pages

Reading Width

760px

Large Headings

Generous Whitespace

Sticky Table of Contents

Optional

Code Blocks

JetBrains Mono

Dark Surface

12px Radius

Horizontal Scrolling

Enabled

---

# Command Palette

Required for desktop applications.

Opens with

Ctrl+K

⌘K

Supports:

Navigation

Actions

Search

Theme

Settings

Recent Items

Appearance

Dark Surface

Rounded

16px

Minimal animations.

---

# Notifications

Notifications should be informative.

Not distracting.

Stack

Maximum

3

Newest First

Auto Dismiss

Optional

Critical notifications remain until dismissed.

---

# File Upload

Support:

Drag & Drop

Browse

Paste

Progress

Retry

File cards should display:

Name

Size

Status

Remove Action

Never hide upload progress.

---

# Design Review Checklist

Before shipping any interface, verify:

✓ Typography follows the defined scale.

✓ Colors come only from the approved palette.

✓ Only one primary action exists per section.

✓ Layout aligns to the grid.

✓ Spacing uses approved spacing tokens.

✓ Borders follow the border system.

✓ Motion remains under 300ms.

✓ Keyboard navigation works.

✓ Contrast passes accessibility requirements.

✓ Empty, loading, success, and error states are defined.

✓ Components match existing patterns.

✓ No unnecessary decoration has been introduced.

If any of these checks fail, revise the design before implementation.

---

# The Short Circuit Standard

Every interface should feel as if it was built by the same team, using the same principles, regardless of when it was created or who designed it.

Users should recognize a Short Circuit product immediately—not because of excessive branding, but because of its disciplined typography, restrained color palette, structured layouts, deliberate spacing, and calm interaction design.

The interface should embody engineering excellence through simplicity, consistency, and precision.

This is the standard every future product, prototype, and marketing experience should uphold.

---

# AI Design Constitution

This section defines the non-negotiable rules every AI assistant, designer, and engineer must follow when creating interfaces for Short Circuit.

If any instruction in this document conflicts with common UI trends or framework defaults, this document takes precedence.

---

# The Short Circuit Test

Every screen should satisfy the following question:

"If the logo were removed, would someone familiar with Short Circuit still recognize this as a Short Circuit product?"

If the answer is no, redesign the interface.

---

# The Five Pillars

Every interface must communicate:

1. Precision

Everything aligns.

Everything feels intentional.

Nothing appears accidental.

---

2. Confidence

The interface never apologizes.

It communicates clearly.

It never overwhelms the user.

---

3. Simplicity

Remove before adding.

Whitespace is preferred over additional UI.

---

4. Engineering

Products should feel designed by engineers with exceptional taste.

Never by marketers chasing trends.

---

5. Timelessness

Avoid trends.

Avoid seasonal aesthetics.

Avoid fashionable UI.

Design for the next decade.

---

# Design Decision Hierarchy

When making design decisions, follow this order.

1.

Usability

↓

2.

Accessibility

↓

3.

Consistency

↓

4.

Hierarchy

↓

5.

Brand Identity

↓

6.

Visual Appeal

Never sacrifice usability for aesthetics.

---

# Default Design Choices

When uncertain:

Use left alignment.

Use white text.

Use dark surfaces.

Use the 8pt spacing system.

Use Poppins.

Use Anton only for major headings.

Use Brand Red only for actions.

Prefer cards over floating panels.

Prefer borders over shadows.

Prefer whitespace over dividers.

Prefer text over icons.

Prefer one action over many.

Prefer fewer controls.

Prefer progressive disclosure.

Prefer consistency over originality.

---

# Things AI Must Never Generate

Never generate:

Glassmorphism

Neumorphism

Pastel colors

Blue primary buttons

Gradient buttons

Floating action buttons

Rounded pill interfaces

Emoji in the interface

Decorative illustrations

Stock photography

Animated backgrounds

Large hero illustrations

Colorful dashboards

Rainbow charts

Card inside card inside card

Excessive drop shadows

Excessive blur

Overly rounded corners

Huge icons

Marketing-style dashboards

Random accent colors

---

# Preferred Design Language

The interface should resemble:

Industrial documentation

Engineering software

Technical publications

Swiss editorial layouts

Architectural presentations

Blueprints

High-end developer tools

Minimal operating system interfaces

It should never resemble:

Gaming software

Crypto dashboards

No-code templates

Consumer mobile apps

Children's software

Corporate PowerPoint slides

---

# Information Density

Interfaces should be information-rich but visually calm.

Do not confuse minimalism with empty space.

Good interfaces show useful information without feeling crowded.

---

# Visual Weight

Large typography carries the page.

Not colors.

Not graphics.

Not shadows.

Typography should create hierarchy.

---

# Use of Color

Black creates focus.

White communicates information.

Red communicates action.

Gray communicates structure.

Nothing else is necessary.

---

# Use of Motion

Motion should answer only one question:

"What changed?"

Never animate for entertainment.

Every animation should communicate state.

---

# Component Philosophy

Components are tools.

Not decoration.

Every component should be reusable.

Predictable.

Accessible.

Composable.

Consistent.

---

# Visual Noise

Reduce visual noise wherever possible.

Before adding:

A border

A shadow

A color

An icon

A divider

Ask:

Can spacing solve this instead?

If yes,

Use spacing.

---

# Empty Space

Whitespace is a design element.

Never attempt to fill every area.

Allow interfaces to breathe.

Premium products have confidence in empty space.

---

# Typography Rules

Typography should establish hierarchy before color.

Increase size before increasing weight.

Increase spacing before adding borders.

Use uppercase sparingly.

Anton should remain exclusive to display typography.

---

# Layout Philosophy

Every layout should feel engineered.

Use consistent alignment.

Use predictable spacing.

Avoid asymmetry unless it serves a clear purpose.

Every page should feel constructed on a grid.

---

# Dashboard Philosophy

Dashboards are workspaces.

Not marketing pages.

Users should immediately understand:

Where they are.

What changed.

What requires attention.

What actions are available.

Everything else is secondary.

---

# Forms Philosophy

Ask only for information that is necessary.

Group related fields.

Avoid multi-column forms on mobile.

Validation should educate rather than punish.

---

# Data Philosophy

Data is the product.

Do not decorate it.

Charts should maximize readability.

Tables should prioritize scanning.

Metrics should prioritize clarity.

---

# Documentation Philosophy

Documentation is a product.

Treat documentation with the same design quality as applications.

Use generous spacing.

Readable typography.

Predictable hierarchy.

Minimal distractions.

---

# Accessibility Philosophy

Accessibility is part of quality.

Not an optional enhancement.

Every interaction should support:

Keyboard

Screen readers

Reduced motion

Sufficient contrast

Touch accessibility

Accessibility should be considered during design, not after implementation.

---

# Responsive Philosophy

Do not simply shrink layouts.

Recompose them.

Mobile interfaces should preserve hierarchy.

Not desktop density.

---

# Engineering Philosophy

Design systems should reduce decisions.

Not create more.

If two buttons solve the same problem,

one should be removed.

If two layouts communicate the same information,

the simpler one should remain.

---

# Brand Recognition

A Short Circuit interface should be recognizable through:

Typography

Spacing

Alignment

Contrast

Component consistency

Interaction quality

Not through excessive logos or branding.

---

# Definition of Done

A screen is complete only when:

✓ Every spacing value follows the spacing system.

✓ Every font follows the typography scale.

✓ Every color comes from the approved palette.

✓ Every interaction has all required states.

✓ Keyboard navigation is complete.

✓ Accessibility requirements pass.

✓ Components reuse existing patterns.

✓ Motion follows approved durations.

✓ Layout aligns to the grid.

✓ Visual hierarchy is immediately understandable.

✓ Nothing unnecessary remains.

---

# Final Principle

Short Circuit products should never attempt to impress through decoration.

They should impress through clarity.

Through precision.

Through discipline.

Through restraint.

The highest compliment a Short Circuit interface can receive is:

"It feels inevitable."

As though no other design could have solved the problem more clearly.
