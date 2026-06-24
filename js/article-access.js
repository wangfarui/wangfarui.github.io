(function () {
  'use strict'

  const textEncoder = new TextEncoder()
  const textDecoder = new TextDecoder()
  const DEFAULT_STORAGE_PREFIX = 'blog_article_access'

  function getConfig () {
    const siteConfig = window.GLOBAL_CONFIG_SITE || {}
    return siteConfig.articleAccess || {}
  }

  function base64UrlToBytes (value) {
    const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/')
    const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - normalized.length % 4)
    const binary = window.atob(normalized + padding)
    const bytes = new Uint8Array(binary.length)

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }

    return bytes
  }

  function parsePayload (article) {
    const payloadNode = article.querySelector('.article-access-payload')
    if (!payloadNode) return null

    try {
      return JSON.parse(payloadNode.textContent)
    } catch (err) {
      return null
    }
  }

  function setMessage (lock, text, type) {
    const message = lock.querySelector('.article-access-message')
    if (!message) return

    message.textContent = text || ''
    message.dataset.type = type || ''
  }

  function setBusy (lock, busy) {
    const submit = lock.querySelector('.article-access-submit')
    const input = lock.querySelector('.article-access-input')

    if (submit) {
      submit.disabled = busy
      submit.textContent = busy ? '校验中...' : '解锁阅读'
    }

    if (input) input.disabled = busy
  }

  function getStoragePrefix () {
    return getConfig().storagePrefix || DEFAULT_STORAGE_PREFIX
  }

  function getStorageKey (type, id) {
    return `${getStoragePrefix()}:${type}:${id}`
  }

  function getStorage (remember) {
    try {
      return remember ? window.localStorage : window.sessionStorage
    } catch (err) {
      return null
    }
  }

  function readStoredCredential (lock) {
    const scope = lock.dataset.scope || 'default'
    const postId = lock.dataset.postId || ''
    const session = getStorage(false)
    const local = getStorage(true)
    const candidates = [
      [session, getStorageKey('post', postId)],
      [session, getStorageKey('scope', scope)],
      [local, getStorageKey('post', postId)],
      [local, getStorageKey('scope', scope)]
    ].filter(([storage]) => storage)

    for (const [storage, key] of candidates) {
      try {
        const raw = storage.getItem(key)
        if (!raw) continue

        const credential = JSON.parse(raw)
        if (credential.expiresAt && Date.parse(credential.expiresAt) <= Date.now()) {
          storage.removeItem(key)
          continue
        }

        if (credential.key) return credential
      } catch (err) {
        try {
          storage.removeItem(key)
        } catch (removeErr) {}
      }
    }

    return null
  }

  function storeCredential (lock, result, remember) {
    const storage = getStorage(remember)
    if (!storage || !result.key) return

    const config = getConfig()
    const scope = result.scope || lock.dataset.scope || 'default'
    const postId = result.postId || lock.dataset.postId || ''
    const defaultExpiresIn = Number(config.defaultExpiresIn || 86400)
    const expiresAt = result.expiresAt ||
      new Date(Date.now() + defaultExpiresIn * 1000).toISOString()
    const accessType = result.access === 'post' ? 'post' : 'scope'
    const id = accessType === 'post' ? postId : scope

    const credential = {
      key: result.key,
      token: result.token || result.accessToken || '',
      scope,
      postId,
      expiresAt
    }

    try {
      storage.setItem(getStorageKey(accessType, id), JSON.stringify(credential))
    } catch (err) {}
  }

  async function decryptArticle (payload, keyValue) {
    const keyBytes = base64UrlToBytes(keyValue)
    const iv = base64UrlToBytes(payload.iv)
    const ciphertext = base64UrlToBytes(payload.ciphertext)
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    )
    const decryptOptions = {
      name: 'AES-GCM',
      iv
    }

    if (payload.aad) {
      decryptOptions.additionalData = textEncoder.encode(payload.aad)
    }

    const plainBuffer = await window.crypto.subtle.decrypt(decryptOptions, cryptoKey, ciphertext)
    return textDecoder.decode(plainBuffer)
  }

  function refreshThemeContent () {
    if (typeof btf !== 'undefined' && typeof btf.removeGlobalFnEvent === 'function') {
      btf.removeGlobalFnEvent('pjax')
    }

    if (typeof window.refreshFn === 'function') {
      window.refreshFn()
    }
  }

  async function unlockArticle (article, lock, payload, keyValue) {
    const html = await decryptArticle(payload, keyValue)
    article.innerHTML = html

    const post = document.getElementById('post')
    if (post) post.classList.add('article-access-unlocked')

    document.dispatchEvent(new window.CustomEvent('article-access:unlocked', {
      detail: {
        postId: payload.postId,
        scope: payload.scope
      }
    }))
    refreshThemeContent()
  }

  async function verifyPassword (lock, password) {
    const config = getConfig()
    const endpoint = config.endpoint

    if (!endpoint) {
      throw new Error('访问校验接口未配置。')
    }

    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), Number(config.requestTimeout || 10000))

    try {
      const response = await window.fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: config.credentials || 'omit',
        signal: controller.signal,
        body: JSON.stringify({
          postId: lock.dataset.postId || '',
          path: lock.dataset.path || window.location.pathname,
          scope: lock.dataset.scope || 'default',
          password
        })
      })

      const json = await response.json().catch(() => ({}))
      const result = json.data || json

      if (!response.ok || result.ok === false || result.success === false) {
        throw new Error(result.message || '访问密码不正确。')
      }

      const key = result.key || result.decryptKey || result.decryptionKey
      if (!key) {
        throw new Error('校验成功，但接口没有返回解密 key。')
      }

      return Object.assign({}, result, { key })
    } finally {
      window.clearTimeout(timeout)
    }
  }

  function setupRememberControl (lock) {
    const config = getConfig()
    const remember = lock.querySelector('.article-access-remember')
    if (remember && config.remember === false) {
      remember.hidden = true
    }
  }

  function setupArticleAccess (lock) {
    if (lock.dataset.accessReady === 'true') return
    lock.dataset.accessReady = 'true'

    const article = document.getElementById('article-container')
    const payload = article && parsePayload(article)
    const form = lock.querySelector('.article-access-form')
    const input = lock.querySelector('.article-access-input')

    setupRememberControl(lock)

    if (!window.crypto || !window.crypto.subtle) {
      setMessage(lock, '当前浏览器不支持 WebCrypto，无法解锁文章。', 'error')
      return
    }

    if (!article || !payload) {
      setMessage(lock, '文章加密数据缺失，无法解锁。', 'error')
      return
    }

    const cachedCredential = readStoredCredential(lock)
    if (cachedCredential) {
      setBusy(lock, true)
      setMessage(lock, '正在恢复访问...', 'info')
      unlockArticle(article, lock, payload, cachedCredential.key)
        .catch(() => {
          setBusy(lock, false)
          setMessage(lock, '已保存的访问凭据失效，请重新输入密码。', 'error')
        })
      return
    }

    if (!form || !input) return

    form.addEventListener('submit', async event => {
      event.preventDefault()

      const password = input.value.trim()
      const rememberInput = form.querySelector('input[name="remember"]')
      const remember = Boolean(rememberInput && rememberInput.checked)

      if (!password) {
        setMessage(lock, '请输入访问密码。', 'error')
        input.focus()
        return
      }

      setBusy(lock, true)
      setMessage(lock, '正在联网校验...', 'info')

      try {
        const result = await verifyPassword(lock, password)
        storeCredential(lock, result, remember)
        await unlockArticle(article, lock, payload, result.key)
      } catch (err) {
        setMessage(lock, err.name === 'AbortError' ? '接口响应超时，请稍后重试。' : err.message, 'error')
        setBusy(lock, false)
      }
    })
  }

  function initArticleAccess () {
    document.querySelectorAll('.article-access-lock').forEach(setupArticleAccess)
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initArticleAccess)
  } else {
    initArticleAccess()
  }

  document.addEventListener('pjax:complete', initArticleAccess)
})()
