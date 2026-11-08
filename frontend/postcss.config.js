/**
 * PostCSS Configuration
 * ============================================================================
 * Required by Tailwind CSS. PostCSS runs Tailwind's compiler first, then
 * Autoprefixer to add vendor prefixes (-webkit-, -moz-) for older browsers.
 *
 * We use ESM syntax (export default) because package.json has `"type": "module"`.
 */

export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};