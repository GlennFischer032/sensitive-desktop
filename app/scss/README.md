# SCSS Style Guide & Structure

This document outlines the organization and best practices for the SCSS codebase of the Sensitive Desktop application.

## Directory Structure

The SCSS is organized following the 7-1 pattern:

- `abstracts/`: Variables, mixins, functions
- `base/`: Reset, typography, animations, etc.
- `components/`: Reusable UI components
- `layout/`: Layout-specific styles
- `pages/`: Page-specific styles
- `themes/`: Theme-related styles
- `vendors/`: Third-party styles

## Style System

### Variables

All design tokens are defined in `abstracts/_variables.scss`:

- **Colors**: Primary, secondary, feedback, text, backgrounds
- **Typography**: Font families, sizes, weights, line heights
- **Spacing**: Consistent spacing scale
- **Borders**: Widths, radii
- **Shadows**: Various elevation levels
- **Transitions**: Durations and timing functions

### Mixins

Common patterns are abstracted into reusable mixins in `abstracts/_mixins.scss`:

- `flex()`: Flexbox utility
- `button-variant()`: Consistent button styles
- `form-control()`: Form input styling
- `respond-to()`: Responsive media queries
- `card()`: Card component styling
- `badge()`: Badge styling
- `heading()`: Typography helpers
- `container()`: Container layouts

## Usage Guidelines

### 1. Use Variables Instead of Hard-coded Values

```scss
// ❌ Bad
.element {
  color: #3498db;
  margin-bottom: 20px;
}

// ✅ Good
.element {
  color: $primary-color;
  margin-bottom: $spacing-md;
}
```

### 2. Use Mixins for Common Patterns

```scss
// ❌ Bad
.card-element {
  background-color: white;
  padding: 16px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

// ✅ Good
.card-element {
  @include card($spacing-md, $bg-white, 1);
}
```

### 3. Responsive Design

Use the responsive mixins for consistent breakpoints:

```scss
.element {
  width: 50%;

  @include respond-to(sm) {
    width: 100%;
  }
}
```

### 4. Component-Based Organization

Keep styles modular and component-specific:

```scss
// components/_buttons.scss
.button {
  // Button base styles

  &.primary {
    // Primary button styles
  }

  &.small {
    // Small button styles
  }
}
```

### 5. BEM Naming Convention

Follow BEM (Block, Element, Modifier) naming convention when possible:

```scss
.card {} // Block
.card__title {} // Element
.card--featured {} // Modifier
```

## Consistency Checklist

- [ ] All color values come from variables
- [ ] Spacing uses the spacing scale variables
- [ ] Common UI patterns use appropriate mixins
- [ ] Components are properly namespaced
- [ ] Responsive designs use the respond-to mixin
- [ ] Typography follows the type scale

## How to Contribute

1. Check the existing styles before adding new ones
2. Reuse existing patterns and variables
3. Document any new variables or mixins
4. Follow the component structure
5. Be mindful of specificity and nesting depth
