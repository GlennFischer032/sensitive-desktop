# Accessibility Guide

This document outlines the accessibility features in our application and how to use them.

## Core Principles

1. **Perceivable**: Information must be presentable to users in ways they can perceive
2. **Operable**: Users must be able to operate the interface
3. **Understandable**: Information and operation must be understandable
4. **Robust**: Content must be robust enough to work with assistive technologies

## Accessibility Features

### Skip Link

The application includes a skip link for keyboard users to bypass navigation:

```html
<a href="#main-content" class="skip-link">Skip to main content</a>
```

The link is visually hidden but appears when focused.

### Keyboard Navigation

All interactive elements must be keyboard accessible:

- Use `tabindex="0"` for elements that aren't natively focusable but should be
- Never use `tabindex` values greater than 0
- Test all interactions with keyboard only

### Focus States

All focusable elements have visible focus states:

```scss
:focus-visible {
  outline: 2px solid $primary-color;
  outline-offset: 2px;
}
```

### ARIA Attributes

Use appropriate ARIA attributes:

- `role` to define element purpose (e.g., `role="dialog"`)
- `aria-label` for providing accessible names
- `aria-labelledby` to reference visible labels
- `aria-describedby` to reference descriptions
- `aria-hidden="true"` for decorative elements
- `aria-live` for dynamic content

### Screen Reader Text

Use the `.sr-only` class for content only available to screen readers:

```html
<span class="sr-only">Additional information for screen readers</span>
```

## Accessible Components

### Modals

Use the modal partial template:

```html
{% from "partials/modal.html" import modal %}
{% call modal("my-modal", "Modal Title") %}
    Modal content goes here
{% endcall %}
```

Include the modal JavaScript:

```html
{% from "partials/modal_js.html" import modal_js %}
{{ modal_js() }}
```

### Forms

Use the form field partials:

```html
{% from "partials/form_fields.html" import input, checkbox, select, form_actions, required_note %}

{{ required_note() }}

{{ input("username", "Username", required=true, help_text="Enter your username", error_id="username-error") }}

{{ select("role", "Role", options=[{"value": "admin", "label": "Administrator"}, {"value": "user", "label": "User"}]) }}

{{ checkbox("remember", "Remember me", help_text="Keep me logged in") }}

{{ form_actions("Save Changes", "Cancel") }}
```

### Tables

Make tables accessible:

```html
<table class="accessible-table">
    <caption>User Information</caption>
    <thead>
        <tr>
            <th scope="col">Name</th>
            <th scope="col">Email</th>
            <th scope="col">Role</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th scope="row">John Doe</th>
            <td>john@example.com</td>
            <td>Administrator</td>
        </tr>
    </tbody>
</table>
```

### Notifications

Make notifications accessible:

```html
<div class="notification-container" role="alert" aria-live="polite">
    <div class="notification success">
        Operation successful
        <span class="notification-close">
            <span class="sr-only">Close notification</span>
        </span>
    </div>
</div>
```

## Testing Accessibility

### Manual Testing

1. **Keyboard Testing**:
   - Tab through the entire page
   - Verify all functionality is accessible
   - Check focus indicators are visible

2. **Screen Reader Testing**:
   - Test with VoiceOver, NVDA, or JAWS
   - Ensure all content is properly announced
   - Verify dynamic content updates are announced

3. **Zoom Testing**:
   - Test with browser zoom at 200%
   - Ensure no content is cut off or overlapping

### Automated Testing

Use these tools to help identify issues:

- [axe](https://www.deque.com/axe/)
- [WAVE](https://wave.webaim.org/)
- [Lighthouse](https://developers.google.com/web/tools/lighthouse)

## Accessibility Standards

Our application aims to meet:

- [WCAG 2.1 AA](https://www.w3.org/TR/WCAG21/)
- [Section 508](https://www.section508.gov/)
- [ADA](https://www.ada.gov/)

## Best Practices

1. Always include proper alt text for images
2. Maintain proper heading hierarchy (h1 → h6)
3. Ensure color is not the only means of conveying information
4. Use sufficient color contrast (minimum 4.5:1 for normal text)
5. Make form elements have associated labels
6. Provide error messages that are clear and descriptive
7. Ensure interactive elements have accessible names
8. Test regularly with assistive technologies

## Utility Classes

### Screen Reader Only Text

```html
<span class="sr-only">Text only for screen readers</span>
```

### Visually Hidden but Focusable

```html
<a href="#main-content" class="sr-only-focusable">Skip to main content</a>
```

### High Contrast Text

```html
<p class="high-contrast-text">This text has higher contrast</p>
```

## Resources

- [WebAIM](https://webaim.org/)
- [A11Y Project](https://www.a11yproject.com/)
- [MDN Accessibility Guide](https://developer.mozilla.org/en-US/docs/Web/Accessibility)
- [Inclusive Components](https://inclusive-components.design/)
- [Accessibility Developer Guide](https://www.accessibility-developer-guide.com/)
