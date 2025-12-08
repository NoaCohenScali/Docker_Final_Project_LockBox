import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import '../styles/PasswordsPage.css'

export default function PasswordsPage() {
  const [passwords, setPasswords] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [title, setTitle] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [editingId, setEditingId] = useState(null)
  const [editPassword, setEditPassword] = useState('')
  const [showAddForm, setShowAddForm] = useState(false)
  const [showPassword, setShowPassword] = useState({})

  const navigate = useNavigate()
  const API_BASE = 'http://localhost:3001'
  const token = localStorage.getItem('token')

  // פונקציה לטיפול ב־401
  const handleAuthFailure = (response, data) => {
    if (response.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('userId')
      setError(data?.message || 'החיבור שלך פג. אנא התחברי מחדש.')
      navigate('/')
      return true
    }
    return false
  }

  // טעינה ראשונית
  useEffect(() => {
    if (!token) {
      navigate('/')
      return
    }
    fetchPasswords()
  }, [token])

  // --- Fetch Passwords ---
  const fetchPasswords = async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/showpasswords`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      const data = await response.json()

      if (!response.ok) {
        if (handleAuthFailure(response, data)) return
        setError(data.message || 'Failed to fetch passwords')
        return
      }

      setPasswords(Array.isArray(data) ? data : [])
    } catch (err) {
      setError('Connection error. Please try again.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  // --- Add Password ---
  const handleAddPassword = async (e) => {
    e.preventDefault()

    if (!title.trim() || !password.trim()) {
      setError('Please fill in all fields')
      return
    }

    setSubmitting(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/addpassword`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ title, password }),
      })

      const data = await response.json()

      if (!response.ok) {
        if (handleAuthFailure(response, data)) return
        setError(data.message || 'Failed to add password')
        return
      }

      setTitle('')
      setPassword('')
      setShowAddForm(false)
      await fetchPasswords()
    } catch (err) {
      setError('Connection error. Please try again.')
      console.error(err)
    } finally {
      setSubmitting(false)
    }
  }

  // --- Update Password ---
  const handleUpdatePassword = async (id) => {
    if (!editPassword.trim()) {
      setError('Please enter a password')
      return
    }

    setSubmitting(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/updatepassword/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ password: editPassword }),
      })

      const data = await response.json()

      if (!response.ok) {
        if (handleAuthFailure(response, data)) return
        setError(data.message || 'Failed to update password')
        return
      }

      setEditingId(null)
      setEditPassword('')
      await fetchPasswords()
    } catch (err) {
      setError('Connection error. Please try again.')
      console.error(err)
    } finally {
      setSubmitting(false)
    }
  }

  // --- Delete Password ---
  const handleDeletePassword = async (id) => {
    if (!window.confirm('Are you sure you want to delete this password?')) {
      return
    }

    setError('')

    try {
      const response = await fetch(`${API_BASE}/deletepassword/${id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      })

      const data = await response.json()

      if (!response.ok) {
        if (handleAuthFailure(response, data)) return
        setError(data.message || 'Failed to delete password')
        return
      }

      await fetchPasswords()
    } catch (err) {
      setError('Connection error. Please try again.')
      console.error(err)
    }
  }

  // --- Logout ---
  const handleLogout = () => {
    localStorage.removeItem('userId')
    localStorage.removeItem('token')
    navigate('/')
  }

  // --- Toggle Show Password ---
  const toggleShowPassword = async (pwd) => {
    setError('')

    if (showPassword[pwd.id]) {
      setShowPassword((prev) => ({
        ...prev,
        [pwd.id]: null,
      }))
      return
    }

    try {
      const response = await fetch(`${API_BASE}/decryptpassword`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          password: pwd.passwords,
          iv: pwd.iv,
        }),
      })

      const text = await response.text()

      if (!response.ok) {
        if (handleAuthFailure(response, { message: text })) return
        throw new Error('Failed to decrypt')
      }

      setShowPassword((prev) => ({
        ...prev,
        [pwd.id]: text,
      }))
    } catch (err) {
      console.error(err)
      setError('Failed to decrypt password')
    }
  }

  // --- JSX ---
  return (
    <div className="passwords-page">
      <header className="passwords-header">
        <div className="header-content">
          <h1>🔑 My Passwords</h1>
          <button onClick={handleLogout} className="btn btn-secondary">
            Logout
          </button>
        </div>
      </header>

      <main className="passwords-main">
        {error && <div className="error-message">{error}</div>}

        <div className="add-password-section">
          {!showAddForm ? (
            <button
              onClick={() => setShowAddForm(true)}
              className="btn btn-primary btn-large"
            >
              + Add New Password
            </button>
          ) : (
            <div className="add-password-form">
              <h2>Add New Password</h2>
              <form onSubmit={handleAddPassword}>
                <div className="form-group">
                  <label htmlFor="title">Title/Name</label>
                  <input
                    id="title"
                    type="text"
                    placeholder="e.g., Gmail, Netflix, etc."
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="new-password">Password</label>
                  <input
                    id="new-password"
                    type="password"
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="form-actions">
                  <button type="submit" className="btn btn-primary" disabled={submitting}>
                    {submitting ? 'Saving...' : 'Save Password'}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      setShowAddForm(false)
                      setTitle('')
                      setPassword('')
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>

        <div className="passwords-list">
          {loading ? (
            <div className="empty-state">
              <p>Loading...</p>
            </div>
          ) : passwords.length === 0 ? (
            <div className="empty-state">
              <p>No passwords saved yet.</p>
              <p>Click "Add New Password" to get started!</p>
            </div>
          ) : (
            <div className="password-items">
              {passwords.map((pwd) => (
                <div key={pwd.id} className="password-item">
                  <div className="password-item-header">
                    <h3>{pwd.title}</h3>
                    <div className="password-item-actions">
                      {editingId === pwd.id ? null : (
                        <>
                          <button
                            onClick={() => toggleShowPassword(pwd)}
                            className="btn-icon"
                            title="Toggle visibility"
                          >
                            {showPassword[pwd.id] ? '👁️' : '👁️‍🗨️'}
                          </button>
                          <button
                            onClick={() => {
                              setEditingId(pwd.id)
                              setEditPassword('')
                            }}
                            className="btn-icon"
                            title="Edit"
                          >
                            ✏️
                          </button>
                          <button
                            onClick={() => handleDeletePassword(pwd.id)}
                            className="btn-icon btn-delete"
                            title="Delete"
                          >
                            🗑️
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  {editingId === pwd.id ? (
                    <div className="edit-form">
                      <input
                        type="password"
                        placeholder="New password"
                        value={editPassword}
                        onChange={(e) => setEditPassword(e.target.value)}
                        autoFocus
                      />
                      <div className="edit-actions">
                        <button
                          onClick={() => handleUpdatePassword(pwd.id)}
                          className="btn btn-small btn-primary"
                          disabled={submitting}
                        >
                          {submitting ? '...' : 'Save'}
                        </button>
                        <button
                          onClick={() => {
                            setEditingId(null)
                            setEditPassword('')
                          }}
                          className="btn btn-small btn-secondary"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="password-display">
                      <code>
                        {showPassword[pwd.id] ? showPassword[pwd.id] : '••••••••'}
                      </code>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
