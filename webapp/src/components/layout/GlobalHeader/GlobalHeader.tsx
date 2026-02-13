'use client'

import Image from 'next/image'
import { ChevronDown } from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import { ProjectSelector } from './ProjectSelector'
import styles from './GlobalHeader.module.css'

export function GlobalHeader() {
  return (
    <header className={styles.header}>
      <div className={styles.logo}>
        <Image src="/logo.png" alt="RedAmon" width={28} height={28} className={styles.logoImg} />
        <span className={styles.logoText}>
          <span className={styles.logoAccent}>Red</span>Amon
        </span>
        <span className={styles.version}>v1.2.0</span>
      </div>

      <div className={styles.spacer} />

      <div className={styles.actions}>
        {/* Project Selector */}
        <ProjectSelector />

        <div className={styles.divider} />

        <ThemeToggle />

        <div className={styles.divider} />

        {/* User Menu - Mock */}
        <button className={styles.userButton}>
          <div className={styles.avatar}>
            <span>RA</span>
          </div>
          <span className={styles.userName}>Admin</span>
          <ChevronDown size={14} />
        </button>
      </div>
    </header>
  )
}
