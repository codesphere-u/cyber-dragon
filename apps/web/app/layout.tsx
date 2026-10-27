import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'Cyber Dragon | Digital safety for everyone', description: 'Check suspicious messages and links, understand risks, and learn to stay safer online.' };
export default function RootLayout({children}: Readonly<{children: React.ReactNode}>) { return <html lang="en"><body>{children}</body></html>; }
