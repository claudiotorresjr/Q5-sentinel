import type { Config } from "tailwindcss";

export default {
	darkMode: ["class"],
	content: [
		"./pages/**/*.{ts,tsx}",
		"./components/**/*.{ts,tsx}",
		"./app/**/*.{ts,tsx}",
		"./src/**/*.{ts,tsx}",
	],
	prefix: "",
	theme: {
		container: {
			center: true,
			padding: '2rem',
			screens: {
				'2xl': '1400px'
			}
		},
		extend: {
			colors: {
				border: 'hsl(var(--border))',
				input: 'hsl(var(--input))',
				ring: 'hsl(var(--ring))',
				background: 'hsl(var(--background))',
				foreground: 'hsl(var(--foreground))',
				primary: {
					DEFAULT: 'hsl(var(--primary))',
					foreground: 'hsl(var(--primary-foreground))'
				},
				secondary: {
					DEFAULT: 'hsl(var(--secondary))',
					foreground: 'hsl(var(--secondary-foreground))'
				},
				destructive: {
					DEFAULT: 'hsl(var(--destructive))',
					foreground: 'hsl(var(--destructive-foreground))'
				},
				muted: {
					DEFAULT: 'hsl(var(--muted))',
					foreground: 'hsl(var(--muted-foreground))'
				},
				accent: {
					DEFAULT: 'hsl(var(--accent))',
					foreground: 'hsl(var(--accent-foreground))'
				},
				popover: {
					DEFAULT: 'hsl(var(--popover))',
					foreground: 'hsl(var(--popover-foreground))'
				},
				card: {
					DEFAULT: 'hsl(var(--card))',
					foreground: 'hsl(var(--card-foreground))'
				},
				// Security-specific colors
				critical: {
					DEFAULT: 'hsl(var(--critical))',
					foreground: 'hsl(var(--critical-foreground))'
				},
				high: {
					DEFAULT: 'hsl(var(--high))',
					foreground: 'hsl(var(--high-foreground))'
				},
				medium: {
					DEFAULT: 'hsl(var(--medium))',
					foreground: 'hsl(var(--medium-foreground))'
				},
				low: {
					DEFAULT: 'hsl(var(--low))',
					foreground: 'hsl(var(--low-foreground))'
				},
				// RPI Score buckets
				'rpi-critical': 'hsl(var(--rpi-critical))',
				'rpi-high': 'hsl(var(--rpi-high))',
				'rpi-medium': 'hsl(var(--rpi-medium))',
				'rpi-low': 'hsl(var(--rpi-low))',
				// Status colors
				kev: 'hsl(var(--kev))',
				poc: 'hsl(var(--poc))',
				'epss-high': 'hsl(var(--epss-high))',
				'epss-medium': 'hsl(var(--epss-medium))',
				'epss-low': 'hsl(var(--epss-low))',
				'sla-violated': 'hsl(var(--sla-violated))',
				'sla-warning': 'hsl(var(--sla-warning))',
				'sla-ok': 'hsl(var(--sla-ok))'
			},
			backgroundImage: {
				'gradient-critical': 'var(--gradient-critical)',
				'gradient-alert': 'var(--gradient-alert)',
				'gradient-success': 'var(--gradient-success)',
				'gradient-hero': 'var(--gradient-hero)'
			},
			boxShadow: {
				'critical': 'var(--shadow-critical)',
				'glow': 'var(--shadow-glow)',
				'card': 'var(--shadow-card)'
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 2px)',
				sm: 'calc(var(--radius) - 4px)'
			},
			keyframes: {
				'accordion-down': {
					from: {
						height: '0'
					},
					to: {
						height: 'var(--radix-accordion-content-height)'
					}
				},
				'accordion-up': {
					from: {
						height: 'var(--radix-accordion-content-height)'
					},
					to: {
						height: '0'
					}
				},
				// Security-specific animations
				'pulse-critical': {
					'0%, 100%': {
						opacity: '1'
					},
					'50%': {
						opacity: '0.6'
					}
				},
				'pulse-glow': {
					'0%, 100%': {
						boxShadow: '0 0 5px hsl(var(--critical) / 0.5)'
					},
					'50%': {
						boxShadow: '0 0 20px hsl(var(--critical) / 0.8), 0 0 30px hsl(var(--critical) / 0.6)'
					}
				},
				'fade-in': {
					'0%': {
						opacity: '0',
						transform: 'translateY(10px)'
					},
					'100%': {
						opacity: '1',
						transform: 'translateY(0)'
					}
				},
				'slide-in': {
					'0%': {
						transform: 'translateX(-100%)'
					},
					'100%': {
						transform: 'translateX(0)'
					}
				}
			},
			animation: {
				'accordion-down': 'accordion-down 0.2s ease-out',
				'accordion-up': 'accordion-up 0.2s ease-out',
				'pulse-critical': 'pulse-critical 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
				'pulse-glow': 'pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
				'fade-in': 'fade-in 0.3s ease-out',
				'slide-in': 'slide-in 0.3s ease-out'
			}
		}
	},
	plugins: [require("tailwindcss-animate")],
} satisfies Config;
