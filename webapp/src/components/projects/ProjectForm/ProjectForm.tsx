'use client'

import { useState } from 'react'
import { Save, X } from 'lucide-react'
import type { Project } from '@prisma/client'
import styles from './ProjectForm.module.css'

// Import sections
import { TargetSection } from './sections/TargetSection'
import { ScanModulesSection } from './sections/ScanModulesSection'
import { NaabuSection } from './sections/NaabuSection'
import { HttpxSection } from './sections/HttpxSection'
import { NucleiSection } from './sections/NucleiSection'
import { KatanaSection } from './sections/KatanaSection'
import { GauSection } from './sections/GauSection'
import { KiterunnerSection } from './sections/KiterunnerSection'
import { CveLookupSection } from './sections/CveLookupSection'
import { MitreSection } from './sections/MitreSection'
import { SecurityChecksSection } from './sections/SecurityChecksSection'
import { GithubSection } from './sections/GithubSection'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ProjectFormProps {
  initialData?: Partial<ProjectFormData>
  onSubmit: (data: ProjectFormData) => Promise<void>
  onCancel: () => void
  isSubmitting?: boolean
  mode: 'create' | 'edit'
}

const TABS = [
  { id: 'target', label: 'Target & Modules' },
  { id: 'port', label: 'Port Scanning' },
  { id: 'http', label: 'HTTP Probing' },
  { id: 'resource', label: 'Resource Enumeration' },
  { id: 'vuln', label: 'Vulnerability Scanning' },
  { id: 'cve', label: 'CVE & MITRE' },
  { id: 'security', label: 'Security Checks' },
  { id: 'integrations', label: 'Integrations' },
] as const

type TabId = typeof TABS[number]['id']

// Default values matching params.py
const getDefaultValues = (): ProjectFormData => ({
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  verifyDomainOwnership: false,
  ownershipToken: 'your-secret-token-here',
  ownershipTxtPrefix: '_redamon-verify',
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
  updateGraphDb: true,
  useTorForRecon: false,
  useBruteforceForSubdomains: true,
  whoisMaxRetries: 6,
  dnsMaxRetries: 3,
  githubAccessToken: '',
  githubTargetOrg: '',
  githubScanMembers: false,
  githubScanGists: true,
  githubScanCommits: true,
  githubMaxCommits: 100,
  githubOutputJson: true,
  naabuDockerImage: 'projectdiscovery/naabu:latest',
  naabuTopPorts: '1000',
  naabuCustomPorts: '',
  naabuRateLimit: 1000,
  naabuThreads: 25,
  naabuTimeout: 10000,
  naabuRetries: 1,
  naabuScanType: 's',
  naabuExcludeCdn: false,
  naabuDisplayCdn: true,
  naabuSkipHostDiscovery: true,
  naabuVerifyPorts: true,
  naabuPassiveMode: false,
  httpxDockerImage: 'projectdiscovery/httpx:latest',
  httpxThreads: 50,
  httpxTimeout: 10,
  httpxRetries: 2,
  httpxRateLimit: 50,
  httpxFollowRedirects: true,
  httpxMaxRedirects: 10,
  httpxProbeStatusCode: true,
  httpxProbeContentLength: true,
  httpxProbeContentType: true,
  httpxProbeTitle: true,
  httpxProbeServer: true,
  httpxProbeResponseTime: true,
  httpxProbeWordCount: true,
  httpxProbeLineCount: true,
  httpxProbeTechDetect: true,
  httpxProbeIp: true,
  httpxProbeCname: true,
  httpxProbeTlsInfo: true,
  httpxProbeTlsGrab: true,
  httpxProbeFavicon: true,
  httpxProbeJarm: true,
  httpxProbeHash: 'sha256',
  httpxIncludeResponse: true,
  httpxIncludeResponseHeaders: true,
  httpxProbeAsn: true,
  httpxProbeCdn: true,
  httpxPaths: [],
  httpxCustomHeaders: [
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language: en-US,en;q=0.9',
    'Accept-Encoding: gzip, deflate',
    'Connection: keep-alive',
    'Upgrade-Insecure-Requests: 1',
    'Sec-Fetch-Dest: document',
    'Sec-Fetch-Mode: navigate',
    'Sec-Fetch-Site: none',
    'Sec-Fetch-User: ?1',
    'Cache-Control: max-age=0',
  ],
  httpxMatchCodes: [],
  httpxFilterCodes: [],
  wappalyzerEnabled: true,
  wappalyzerMinConfidence: 50,
  wappalyzerRequireHtml: true,
  wappalyzerAutoUpdate: true,
  wappalyzerNpmVersion: '6.10.56',
  wappalyzerCacheTtlHours: 24,
  bannerGrabEnabled: true,
  bannerGrabTimeout: 5,
  bannerGrabThreads: 20,
  bannerGrabMaxLength: 500,
  nucleiSeverity: ['critical', 'high', 'medium', 'low'],
  nucleiTemplates: [],
  nucleiExcludeTemplates: [],
  nucleiCustomTemplates: [],
  nucleiRateLimit: 100,
  nucleiBulkSize: 25,
  nucleiConcurrency: 25,
  nucleiTimeout: 10,
  nucleiRetries: 1,
  nucleiTags: [],
  nucleiExcludeTags: [],
  nucleiDastMode: true,
  nucleiAutoUpdateTemplates: true,
  nucleiNewTemplatesOnly: false,
  nucleiHeadless: false,
  nucleiSystemResolvers: true,
  nucleiFollowRedirects: true,
  nucleiMaxRedirects: 10,
  nucleiScanAllIps: false,
  nucleiInteractsh: true,
  nucleiDockerImage: 'projectdiscovery/nuclei:latest',
  katanaDockerImage: 'projectdiscovery/katana:latest',
  katanaDepth: 2,
  katanaMaxUrls: 500,
  katanaRateLimit: 50,
  katanaTimeout: 900,
  katanaJsCrawl: true,
  katanaParamsOnly: false,
  katanaExcludePatterns: [
    // Next.js / React
    '/_next/image', '/_next/static', '/_next/data', '/__nextjs',
    // Nuxt.js / Vue.js
    '/_nuxt/', '/__nuxt',
    // Angular
    '/runtime.', '/polyfills.', '/vendor.',
    // Webpack / Build Tools
    '/webpack', '/chunk.', '.chunk.js', '.bundle.js', 'hot-update',
    // Static Files / CDN
    '/static/', '/public/', '/dist/', '/build/', '/lib/', '/vendor/', '/node_modules/',
    // Images
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
    '.bmp', '.tiff', '.tif', '.heic', '.heif', '.raw',
    '/images/', '/img/', '/image/', '/pics/', '/pictures/',
    '/thumbnails/', '/thumb/', '/thumbs/',
    // CSS / Stylesheets
    '.css', '.scss', '.sass', '.less', '.styl', '.css.map',
    '/css/', '/styles/', '/style/', '/stylesheet/',
    // JavaScript (non-application)
    '.js.map', '.min.js', '/js/lib/', '/js/vendor/', '/js/plugins/',
    'jquery', 'bootstrap.js', 'popper.js',
    // Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '/fonts/', '/font/', '/webfonts/',
    // Documents / Downloads
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.rtf', '.odt', '.ods', '.odp',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    // Audio / Video
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
    '.wav', '.ogg', '.aac', '.m4a', '.flac',
    '/video/', '/videos/', '/audio/', '/music/', '/sounds/',
    // WordPress
    '/wp-content/uploads/', '/wp-content/themes/', '/wp-includes/',
    // Drupal
    '/sites/default/files/', '/core/assets/',
    // Magento
    '/pub/static/', '/pub/media/',
    // Laravel / PHP
    '/storage/',
    // Django / Python
    '/staticfiles/',
    // Ruby on Rails
    '/packs/',
    // CDN / External Resources
    'cdn.', 'cdnjs.', 'cloudflare.', 'akamai.', 'fastly.',
    'googleapis.com', 'gstatic.com', 'cloudfront.net',
    'unpkg.com', 'jsdelivr.net', 'bootstrapcdn.com',
    // Analytics / Tracking
    'google-analytics', 'googletagmanager', 'gtag/',
    'facebook.com/tr', 'facebook.net',
    'analytics.', 'tracking.', 'pixel.',
    'hotjar.', 'mouseflow.', 'clarity.',
    // Ads
    'googlesyndication', 'doubleclick', 'adservice',
    // Social Media Widgets
    'platform.twitter', 'connect.facebook', 'platform.linkedin',
    // Maps
    'maps.google', 'maps.googleapis', 'openstreetmap', 'mapbox',
    // Captcha / Security
    'recaptcha', 'hcaptcha', 'captcha',
    // Manifest / Service Workers / Config
    'manifest.json', 'sw.js', 'service-worker',
    'browserconfig.xml', 'robots.txt', 'sitemap.xml', '.well-known/',
    // Favicon / Icons
    'favicon', 'apple-touch-icon', 'android-chrome', '/icons/', '/icon/',
  ],
  katanaScope: 'dn',
  katanaCustomHeaders: [
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language: en-US,en;q=0.9',
  ],
  gauEnabled: false,
  gauDockerImage: 'sxcurity/gau:latest',
  gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
  gauMaxUrls: 1000,
  gauTimeout: 60,
  gauThreads: 5,
  gauBlacklistExtensions: [
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'avif',
    'css', 'woff', 'woff2', 'ttf', 'eot', 'otf',
    'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'zip', 'rar', '7z', 'tar', 'gz',
  ],
  gauYearRange: [],
  gauVerbose: false,
  gauVerifyUrls: true,
  gauVerifyDockerImage: 'projectdiscovery/httpx:latest',
  gauVerifyTimeout: 5,
  gauVerifyRateLimit: 100,
  gauVerifyThreads: 50,
  gauVerifyAcceptStatus: [200, 201, 301, 302, 307, 308, 401, 403],
  gauDetectMethods: true,
  gauMethodDetectTimeout: 5,
  gauMethodDetectRateLimit: 50,
  gauMethodDetectThreads: 25,
  gauFilterDeadEndpoints: true,
  kiterunnerEnabled: true,
  kiterunnerWordlists: ['routes-large'],
  kiterunnerRateLimit: 100,
  kiterunnerConnections: 100,
  kiterunnerTimeout: 10,
  kiterunnerScanTimeout: 1000,
  kiterunnerThreads: 50,
  kiterunnerIgnoreStatus: [404, 400, 502, 503],
  kiterunnerMinContentLength: 0,
  kiterunnerMatchStatus: [],
  kiterunnerHeaders: [],
  kiterunnerDetectMethods: true,
  kiterunnerMethodDetectionMode: 'bruteforce',
  kiterunnerBruteforceMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],
  kiterunnerMethodDetectTimeout: 5,
  kiterunnerMethodDetectRateLimit: 50,
  kiterunnerMethodDetectThreads: 25,
  cveLookupEnabled: true,
  cveLookupSource: 'nvd',
  cveLookupMaxCves: 20,
  cveLookupMinCvss: 0.0,
  vulnersApiKey: '',
  nvdApiKey: '',
  mitreAutoUpdateDb: true,
  mitreIncludeCwe: true,
  mitreIncludeCapec: true,
  mitreEnrichRecon: true,
  mitreEnrichGvm: true,
  mitreCacheTtlHours: 24,
  securityCheckEnabled: true,
  securityCheckDirectIpHttp: true,
  securityCheckDirectIpHttps: true,
  securityCheckIpApiExposed: true,
  securityCheckWafBypass: true,
  securityCheckTlsExpiringSoon: true,
  securityCheckTlsExpiryDays: 30,
  securityCheckMissingReferrerPolicy: true,
  securityCheckMissingPermissionsPolicy: true,
  securityCheckMissingCoop: true,
  securityCheckMissingCorp: true,
  securityCheckMissingCoep: true,
  securityCheckCacheControlMissing: true,
  securityCheckLoginNoHttps: true,
  securityCheckSessionNoSecure: true,
  securityCheckSessionNoHttponly: true,
  securityCheckBasicAuthNoTls: true,
  securityCheckSpfMissing: true,
  securityCheckDmarcMissing: true,
  securityCheckDnssecMissing: true,
  securityCheckZoneTransfer: true,
  securityCheckAdminPortExposed: true,
  securityCheckDatabaseExposed: true,
  securityCheckRedisNoAuth: true,
  securityCheckKubernetesApiExposed: true,
  securityCheckSmtpOpenRelay: true,
  securityCheckCspUnsafeInline: true,
  securityCheckInsecureFormAction: true,
  securityCheckNoRateLimiting: true,
  securityCheckTimeout: 10,
  securityCheckMaxWorkers: 10,
})

export function ProjectForm({
  initialData,
  onSubmit,
  onCancel,
  isSubmitting = false,
  mode
}: ProjectFormProps) {
  const [activeTab, setActiveTab] = useState<TabId>('target')
  const [formData, setFormData] = useState<ProjectFormData>(() => ({
    ...getDefaultValues(),
    ...initialData
  }))

  const updateField = <K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      alert('Project name is required')
      return
    }

    if (!formData.targetDomain.trim()) {
      alert('Target domain is required')
      return
    }

    await onSubmit(formData)
  }

  return (
    <form onSubmit={handleSubmit} className={styles.form}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          {mode === 'create' ? 'Create New Project' : 'Project Settings'}
        </h1>
        <div className={styles.actions}>
          <button
            type="button"
            className="secondaryButton"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            <X size={14} />
            Cancel
          </button>
          <button
            type="submit"
            className="primaryButton"
            disabled={isSubmitting}
          >
            <Save size={14} />
            {isSubmitting ? 'Saving...' : 'Save Project'}
          </button>
        </div>
      </div>

      <div className={styles.tabs}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            type="button"
            className={`tab ${activeTab === tab.id ? 'tabActive' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className={styles.content}>
        {activeTab === 'target' && (
          <>
            <TargetSection data={formData} updateField={updateField} />
            <ScanModulesSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'port' && (
          <NaabuSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'http' && (
          <HttpxSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'resource' && (
          <>
            <KatanaSection data={formData} updateField={updateField} />
            <GauSection data={formData} updateField={updateField} />
            <KiterunnerSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'vuln' && (
          <NucleiSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'cve' && (
          <>
            <CveLookupSection data={formData} updateField={updateField} />
            <MitreSection data={formData} updateField={updateField} />
          </>
        )}

        {activeTab === 'security' && (
          <SecurityChecksSection data={formData} updateField={updateField} />
        )}

        {activeTab === 'integrations' && (
          <GithubSection data={formData} updateField={updateField} />
        )}
      </div>
    </form>
  )
}

export default ProjectForm
