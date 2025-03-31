# Sass Architecture

This project uses a 7-1 Sass architecture pattern for organizing CSS. This structure helps maintain a clean, scalable, and maintainable codebase.

## Directory Structure

```
scss/
|– abstracts/            # Variables, mixins, functions
|– base/                 # Base styles, typography, animations
|– components/           # Reusable components
|– layout/               # Layout sections
|– pages/                # Page-specific styles
|– themes/               # Theming
|– vendors/              # External libraries
|
|– main.scss             # Main file that imports all partials
```

## Getting Started

### Prerequisites

- Install Sass:
```bash
pip install sass
```

### Building CSS

To compile Sass to CSS:

```bash
# One-time build
python -m sass app/scss/main.scss:app/static/style.css

# Watch for changes
python -m sass --watch app/scss/main.scss:app/static/style.css

# Build for production (compressed)
python -m sass --style=compressed app/scss/main.scss:app/static/style.css
```

## Usage

### Adding a New Component

1. Create a new file in the appropriate directory (e.g., `_mycomponent.scss` in `components/`)
2. Add your styles using Sass syntax
3. Import your new file in `main.scss`:
   ```scss
   // Components
   @import 'components/mycomponent';
   ```

### Using Variables

Variables are defined in `abstracts/_variables.scss`:

```scss
// Example usage
.my-element {
  color: $primary-color;
  margin: $spacing-md;
}
```

### Using Mixins

Mixins are defined in `abstracts/_mixins.scss`:

```scss
// Example usage
.my-component {
  @include flex(row, center, center);
  @include button-variant($success-color);
}
```

## Best Practices

1. **Use Variables**: Always use variables for colors, spacing, etc.
2. **Be Component-Oriented**: Create modular, reusable components
3. **Follow Naming Conventions**: Use BEM (Block Element Modifier) convention
4. **Keep Responsive Design in Mind**: Use mixins for consistency
5. **Comment Your Code**: Add comments to explain complex styles

## Maintenance

To maintain the codebase:

1. Regularly review and clean up unused styles
2. Keep files small and focused
3. Update variables when design changes
4. Refactor components when needed
