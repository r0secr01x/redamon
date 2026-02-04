'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, FolderOpen, Users, RefreshCw } from 'lucide-react'
import Link from 'next/link'
import { useProjects, useDeleteProject } from '@/hooks/useProjects'
import { useUsers, useCreateUser } from '@/hooks/useUsers'
import { useProject } from '@/providers/ProjectProvider'
import { ProjectCard } from '@/components/projects/ProjectCard'
import styles from './page.module.css'

export default function ProjectsPage() {
  const router = useRouter()
  const { userId, setUserId, setCurrentProject } = useProject()
  const [showUserModal, setShowUserModal] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [newUserEmail, setNewUserEmail] = useState('')

  const { data: users, isLoading: usersLoading } = useUsers()
  const { data: projects, isLoading: projectsLoading, refetch } = useProjects(userId || undefined)
  const deleteProjectMutation = useDeleteProject()
  const createUserMutation = useCreateUser()

  // Auto-select first user if none selected and users exist
  useEffect(() => {
    if (!userId && users && users.length > 0) {
      setUserId(users[0].id)
    }
  }, [userId, users, setUserId])

  const handleSelectProject = (project: { id: string; name: string; targetDomain: string }) => {
    setCurrentProject({
      id: project.id,
      name: project.name,
      targetDomain: project.targetDomain,
      createdAt: '',
      updatedAt: ''
    })
    router.push(`/graph?project=${project.id}`)
  }

  const handleDeleteProject = async (projectId: string) => {
    if (confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      await deleteProjectMutation.mutateAsync(projectId)
    }
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const user = await createUserMutation.mutateAsync({
        name: newUserName,
        email: newUserEmail
      })
      setUserId(user.id)
      setShowUserModal(false)
      setNewUserName('')
      setNewUserEmail('')
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Failed to create user')
    }
  }

  const isLoading = usersLoading || projectsLoading

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <FolderOpen size={20} />
          <h1 className={styles.title}>Projects</h1>
        </div>
        <div className={styles.headerActions}>
          <button
            className="iconButton"
            onClick={() => refetch()}
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          <Link href="/projects/new" className="primaryButton">
            <Plus size={14} />
            New Project
          </Link>
        </div>
      </div>

      <div className={styles.userSelector}>
        <div className={styles.userSelectorLabel}>
          <Users size={14} />
          <span>User:</span>
        </div>
        <select
          className="select"
          value={userId || ''}
          onChange={(e) => setUserId(e.target.value || null)}
        >
          <option value="">Select a user</option>
          {users?.map((user) => (
            <option key={user.id} value={user.id}>
              {user.name} ({user.email})
            </option>
          ))}
        </select>
        <button
          className="secondaryButton"
          onClick={() => setShowUserModal(true)}
        >
          <Plus size={12} />
          New User
        </button>
      </div>

      {isLoading ? (
        <div className={styles.loading}>Loading...</div>
      ) : !userId ? (
        <div className={styles.empty}>
          <Users size={48} />
          <h2>No User Selected</h2>
          <p>Select a user or create a new one to view projects.</p>
          <button
            className="primaryButton"
            onClick={() => setShowUserModal(true)}
          >
            <Plus size={14} />
            Create User
          </button>
        </div>
      ) : projects && projects.length > 0 ? (
        <div className={styles.grid}>
          {projects.map((project) => (
            <ProjectCard
              key={project.id}
              id={project.id}
              name={project.name}
              targetDomain={project.targetDomain}
              description={project.description}
              createdAt={project.createdAt}
              onSelect={() => handleSelectProject(project)}
              onDelete={() => handleDeleteProject(project.id)}
            />
          ))}
        </div>
      ) : (
        <div className={styles.empty}>
          <FolderOpen size={48} />
          <h2>No Projects Yet</h2>
          <p>Create your first project to get started with reconnaissance.</p>
          <Link href="/projects/new" className="primaryButton">
            <Plus size={14} />
            Create Project
          </Link>
        </div>
      )}

      {showUserModal && (
        <div className={styles.modalOverlay} onClick={() => setShowUserModal(false)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Create New User</h2>
            <form onSubmit={handleCreateUser}>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Name</label>
                <input
                  type="text"
                  className="textInput"
                  value={newUserName}
                  onChange={(e) => setNewUserName(e.target.value)}
                  placeholder="Enter user name"
                  required
                />
              </div>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Email</label>
                <input
                  type="email"
                  className="textInput"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  placeholder="Enter email address"
                  required
                />
              </div>
              <div className={styles.modalActions}>
                <button
                  type="button"
                  className="secondaryButton"
                  onClick={() => setShowUserModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primaryButton"
                  disabled={createUserMutation.isPending}
                >
                  {createUserMutation.isPending ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
