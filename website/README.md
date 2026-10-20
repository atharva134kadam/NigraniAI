# NigraniAI Landing Page

Professional landing page for NigraniAI — an intelligent privacy and compliance monitoring platform.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Supabase

Copy the example environment file and add your Supabase credentials:

```bash
cp .env.example .env.local
```

Edit `.env.local` and add your values:

```env
VITE_SUPABASE_URL=https://tanbqxisjwplkfdjsxsk.supabase.co
VITE_SUPABASE_ANON_KEY=your_public_anon_key_here
```

> **Important**: Never commit `.env.local` to version control. It's already in `.gitignore`.

### 3. Set Up Supabase Database

Run the SQL schema in your Supabase SQL Editor:

1. Go to your Supabase project dashboard
2. Navigate to **SQL Editor**
3. Copy and paste the contents of `supabase/schema.sql`
4. Click **Run**

This creates the `demo_bookings` table with Row Level Security policies.

### 4. Start Development Server

```bash
npm run dev
```

The site will be available at `http://localhost:3000`

### 5. Build for Production

```bash
npm run build
```

Output will be in the `dist/` directory.

### 6. Preview Production Build

```bash
npm run preview
```

## 📁 Project Structure

```
NigraniAI landing_page/
├── public/
│   └── images/
│       └── nigraniai-logo.jpeg      # Official logo (do not modify)
├── src/
│   ├── components/
│   │   ├── Navbar.tsx               # Sticky navbar with mobile menu
│   │   ├── Hero.tsx                 # Hero section with dashboard preview
│   │   ├── DashboardPreview.tsx     # Illustrative dashboard interface
│   │   ├── ProblemSection.tsx       # 6 problem cards
│   │   ├── Capabilities.tsx         # 6 expandable capability cards
│   │   ├── HowItWorks.tsx           # 8-step workflow
│   │   ├── DPDPASection.tsx         # FAQ accordion about DPDPA
│   │   ├── WhyNigraniAI.tsx         # 4 benefit cards + statement
│   │   ├── About.tsx                # Mission, vision, principles
│   │   ├── DemoBooking.tsx          # Form with Supabase integration
│   │   ├── CookieConsent.tsx        # Horizontal banner + settings panel
│   │   └── Footer.tsx               # Footer with legal pages
│   ├── lib/
│   │   └── supabase.ts              # Supabase client & submission function
│   ├── utils/
│   │   └── scroll.ts                # Smooth scroll utility
│   ├── App.tsx                      # Main app component
│   ├── main.tsx                     # Entry point
│   └── index.css                    # Global styles & design tokens
├── supabase/
│   └── schema.sql                   # Database schema & RLS policies
├── .env.example                     # Environment template
├── .gitignore
├── index.html
├── package.json
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts
└── README.md
```

## ✨ Features

- **React 18 + TypeScript + Vite** — Fast, modern stack
- **Framer Motion** — Smooth animations & transitions
- **Lucide React** — Consistent icon system
- **Supabase** — Serverless demo booking storage
- **Cookie Consent** — GDPR/DPDPA compliant banner
- **Responsive** — Mobile-first, works on all devices
- **Accessible** — Semantic HTML, ARIA labels, focus management
- **Design System** — CSS custom properties for consistent theming

## 🎨 Design Tokens

All colours, spacing, typography, and shadows are defined as CSS custom properties in `src/index.css`:

```css
:root {
  --color-primary: #1e3a5f;       /* Deep Navy */
  --color-accent: #00b4d8;        /* Electric Blue */
  --color-text-primary: #1a2a3a;  /* Charcoal */
  --color-bg-primary: #ffffff;    /* White */
  /* ... more tokens */
}
```

## 🔧 Demo Booking Form

The form validates all required fields client-side before submitting to Supabase:

- **Honeypot field** — Reduces spam
- **Email format validation**
- **Phone number validation**
- **Date picker** — Prevents past dates
- **Loading & error states**
- **Unique booking reference** generated on success

Submissions are stored in the `demo_bookings` table with `PENDING` status.

## 🍪 Cookie Consent

Horizontal banner at bottom with three options:

- **Accept All** — Necessary + Analytics + Marketing
- **Reject Optional** — Necessary only
- **Customise** — Granular control per category

Preferences persisted in `localStorage` with versioning. Re-openable from footer.

## 📝 Legal Pages

Privacy Policy and Terms & Conditions are included as hidden sections in the footer (`#privacy-policy`, `#terms-conditions`). They are not separate routes — this avoids broken links and keeps the project simple.

## ♿ Accessibility

- Skip link for keyboard users
- Semantic HTML5 landmarks
- ARIA labels & roles
- Focus-visible outlines
- Reduced motion support
- Sufficient colour contrast

## 🧪 Testing Checklist

- [ ] `npm run dev` starts without errors
- [ ] No TypeScript errors (`npm run build`)
- [ ] Navbar links scroll to correct sections
- [ ] Mobile menu opens/closes
- [ ] Hero buttons scroll to correct sections
- [ ] Capability cards expand/collapse
- [ ] DPDPA FAQ accordion works
- [ ] Demo form validates & submits
- [ ] Supabase record appears in dashboard
- [ ] Cookie banner appears on first visit
- [ ] Cookie preferences persist
- [ ] Cookie settings re-open from footer
- [ ] Responsive on mobile/tablet/desktop
- [ ] No horizontal scroll
- [ ] No console errors

## 📦 Deployment

The `dist/` folder can be deployed to any static hosting:

- **Vercel**: `vercel --prod`
- **Netlify**: Drag & drop `dist/` or connect repo
- **AWS S3 + CloudFront**
- **GitHub Pages**: Configure in repo settings

Ensure environment variables are set in your hosting provider's dashboard.

## 📄 License

Proprietary — All rights reserved. NigraniAI © 2025