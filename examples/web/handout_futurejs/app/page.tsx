'use client'

import { useMemo, useState } from 'react'
import { Bebas_Neue, Lora } from 'next/font/google'
import styles from './page.module.css'
import episodeData from '../data/doctor-who-episodes.json'

type Episode = {
  anchorId: string
  storyNumber: string
  numberInSeries: string
  title: string
  doctor: string
  series: string
  directedBy: string
  writtenBy: string
  originalReleaseDate: string
  productionCode: string
  ukViewersMillions: string
  appreciationIndex: string
}

const displayFont = Bebas_Neue({
  weight: '400',
  subsets: ['latin'],
})

const bodyFont = Lora({
  subsets: ['latin'],
  weight: ['400', '600', '700'],
})

const episodes = episodeData.episodes as Episode[]

function pickEpisode(list: Episode[], lastAnchorId?: string): Episode {
  if (list.length === 0) {
    throw new Error('No episodes available')
  }

  if (list.length === 1) {
    return list[0]
  }

  let candidate = list[Math.floor(Math.random() * list.length)]
  while (candidate.anchorId === lastAnchorId) {
    candidate = list[Math.floor(Math.random() * list.length)]
  }

  return candidate
}

export default function Page() {
  const [picked, setPicked] = useState<Episode | null>(null)

  const introCount = useMemo(() => episodes.length, [])

  function handlePick() {
    const episode = pickEpisode(episodes, picked?.anchorId)
    setPicked(episode)
  }

  return (
    <main className={`${styles.page} ${bodyFont.className}`}>
      <div className={styles.vortex} aria-hidden="true" />

      <header className={styles.hero}>
        <p className={styles.kicker}></p>
        <h1 className={`${styles.title} ${displayFont.className}`}>Doctor Who</h1>
        <p className={styles.subtitle}>
          Pulling from your local archive of {introCount} episodes! Press the button and let the
          TARDIS decide your night.
        </p>
      </header>

      <section className={styles.controlPanel}>
        <button type="button" className={styles.pickButton} onClick={handlePick}>
          Pick Me An Episode
        </button>
        <p className={styles.helper}>No destiny, no spreadsheet, no overthinking.</p>
      </section>

      <section className={styles.resultPanel}>
        {picked ? (
          <article className={styles.card}>
            <p className={styles.cardKicker}>Your Watch Order Is</p>
            <h2 className={`${styles.episodeTitle} ${displayFont.className}`}>{picked.title}</h2>
            <dl className={styles.metaGrid}>
              <div>
                <dt>Doctor</dt>
                <dd>{picked.doctor}</dd>
              </div>
              <div>
                <dt>Series</dt>
                <dd>{picked.series}</dd>
              </div>
              <div>
                <dt>Story #</dt>
                <dd>{picked.storyNumber}</dd>
              </div>
              <div>
                <dt>Original Air Date</dt>
                <dd>{picked.originalReleaseDate}</dd>
              </div>
              <div>
                <dt>Directed By</dt>
                <dd>{picked.directedBy}</dd>
              </div>
              <div>
                <dt>Written By</dt>
                <dd>{picked.writtenBy}</dd>
              </div>
            </dl>
          </article>
        ) : (
          <article className={styles.placeholder}>
            <h2 className={`${styles.placeholderTitle} ${displayFont.className}`}>Alons-y!</h2>
            <p>Hit the button and I will pick one random episode from the revived era list.</p>
          </article>
        )}
      </section>

    </main>
  )
}
