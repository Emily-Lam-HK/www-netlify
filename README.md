# emilylam.hk

- `public/` — the website (`index.html`) and your admin page (`admin.html`)
- `netlify/functions/api.mjs` — the backend: Log, status, document unlock, requests
- `netlify.toml`, `package.json` — settings Netlify reads automatically

## Common mistakes (why a deploy shows "Page not found")
- **Don't drag the .zip onto Netlify.** Unzip it first.
- **Netlify's drag-and-drop can't run the backend** (admin page, unlock, requests, Log). Use GitHub as below.
- **Upload what's *inside* the folder, not the folder itself**, so `netlify.toml` sits at the top of the repo.
  (If the repo already has an `emilylam-site` folder at the top, set Netlify → Site configuration →
  Build & deploy → Base directory to `emilylam-site`.)

## One-time setup

1. **GitHub:** create a new private repository (e.g. `emilylam-site`), choose
   "uploading an existing file", and drag in everything in this folder. Commit.
2. **Netlify:** Add new site → Import an existing project → GitHub → pick the repo → Deploy.
3. **Resend (sends the 6-digit codes and approval emails):** sign up at resend.com,
   add the domain `emilylam.hk`, add the DNS records it shows, then create an API key.
4. **Netlify → Site configuration → Environment variables**, add:
   | Name | Value |
   |---|---|
   | `ADMIN_PASSWORD` | the password for your admin page (make it long) |
   | `SESSION_SECRET` | any long random text, 40+ characters, never shared |
   | `RESEND_API_KEY` | the key from Resend |
   | `MAIL_FROM` | `Emily Lam <hello@emilylam.hk>` |
   | `OWNER_EMAIL` | `me@emilylam.hk` (where request alerts go) |
   | `SITE_URL` | `https://emilylam.hk` |
   Then Deploys → Trigger deploy.
5. **Domain:** Domain management → Add custom domain → `emilylam.hk`. Keep the `meet` DNS record as it is.

## Everyday use — emilylam.hk/admin.html

- **Status:** tap one; the home page updates straight away.
- **Log:** write a post and add up to 8 photos. Photos are re-drawn in your browser before upload, which
  removes location, camera and other hidden details; the server strips any that remain. Edit or delete posts any time.
- **Links:** edit names, addresses, notes, colours and icons, reorder them, add or delete links,
  and upload a logo. Each link's QR code uses its colour, with its logo or icon in the middle.
- **Documents:** add, rename, move, reorder or delete the locked items on your home page
  (Documents, Portfolio, Certificates & prizes, Books, Past projects). Upload each file (up to 4 MB)
  or paste a link for bigger ones. Set the documents password here too.
- **Requests:** approve to email the visitor a private link (works 14 days), or decline.

Visitors unlock by verifying their email with a 6-digit code, then entering the documents password.
