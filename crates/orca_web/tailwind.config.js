/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    files: ["*.html", "./src/**/*.rs"],
    transform: {
      rs: (content) => content.replace(/(?:^|\s)class:/g, ' '),
    },
  },
  theme: {
    /* extend: {
      colors: {
        'darkest': '#27374D',
        'dark': '#526D82',
        'light': '#9DB2BF',
        'lightest': '#DDE6ED',
      }
    }, */
    extend: {
      colors: {
        // Base
        dark: {
          a0: "#000000",
        },
        light: {
          a0: "#ffffff",
        },

        // Primary
        primary: {
          a0: "#2b62e3",
          a10: "#5272e7",
          a20: "#6e82ea",
          a30: "#8693ee",
          a40: "#9ca4f1",
          a50: "#b1b5f4",
        },

        // Surface
        surface: {
          a0: "#121212",
          a10: "#282828",
          a20: "#3f3f3f",
          a30: "#575757",
          a40: "#717171",
          a50: "#8b8b8b",
        },

        // Tonal Surface
        "surface-tonal": {
          a0: "#191a24",
          a10: "#2e2f39",
          a20: "#45454e",
          a30: "#5d5d65",
          a40: "#75767d",
          a50: "#8f9096",
        },

        // Success
        success: {
          a0: "#22946e",
          a10: "#47d5a6",
          a20: "#9ae8ce",
        },

        // Warning
        warning: {
          a0: "#a87a2a",
          a10: "#d7ac61",
          a20: "#ecd7b2",
        },

        // Danger
        danger: {
          a0: "#9c2121",
          a10: "#d94a4a",
          a20: "#eb9e9e",
        },

        // Info
        info: {
          a0: "#21498a",
          a10: "#4077d1",
          a20: "#92b2e5",
        },
      },
    },
  },
  plugins: [],
}
