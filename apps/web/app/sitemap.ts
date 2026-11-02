import type { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: 'https://cyber-dragon-ivory.vercel.app/',
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: 'https://cyber-dragon-ivory.vercel.app/learn',
      changeFrequency: 'monthly',
      priority: 0.8,
    },
  ];
}
