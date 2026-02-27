(function (global) {
  if (global.MessengerWidget) return;

  var DEFAULTS = {
    title: 'Meddelanden',
    primaryColor: '#0084ff',
    launcherSize: 60,
    bottom: 24,
    sideOffset: 24,
    position: 'right',
    fixed: true,
    hideLauncher: false,
    width: 380,
    height: 600,
    zIndex: 2147483000,
    apiBase: '',
    widgetId: 'default',
    me: { id: '', name: 'Du' },
    users: [],
    conversations: []
  };

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function nowTime() {
    var d = new Date();
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  function id(prefix) {
    return prefix + '-' + Math.random().toString(36).slice(2, 9);
  }

  function hashCode(value) {
    var str = String(value || '');
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  function nameInitials(name) {
    var parts = String(name || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (!parts.length) return '?';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  function colorFor(value) {
    var hue = hashCode(value) % 360;
    return 'hsl(' + hue + ', 72%, 46%)';
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatBytes(bytes) {
    var size = Number(bytes) || 0;
    if (size < 1024) return size + ' B';
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + ' KB';
    return (size / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function isImageType(type) {
    return /^image\//i.test(String(type || ''));
  }

  function toFiniteNumber(value, fallback) {
    var num = Number(value);
    return Number.isFinite(num) ? num : fallback;
  }

  function normalizeUser(user) {
    var idValue = user && user.id != null ? String(user.id) : '';
    var nameValue = String((user && (user.name || user.username)) || 'Okand anvandare').trim();
    return {
      id: idValue,
      name: nameValue,
      initials: String(user && user.initials ? user.initials : nameInitials(nameValue)),
      color: String(user && user.color ? user.color : colorFor(idValue || nameValue)),
      online: !!(user && user.online)
    };
  }

  function Widget(options) {
    this.options = Object.assign({}, DEFAULTS, options || {});
    this.state = {
      open: false,
      activeConvoId: null,
      pendingFiles: [],
      me: clone(this.options.me),
      users: clone(this.options.users),
      conversations: clone(this.options.conversations),
      unreadByConvo: {}
    };

    this._host = null;
    this._root = null;
    this._els = {};
    this._replyTimer = null;
    this._pollTimer = null;
    this._toastTimer = null;
    this._inputId = id('mw-file');
    this._docKeydownHandler = null;
    this._docClickHandler = null;
    this._hasBootstrappedConversations = false;
    this._lightboxZoom = 1;
    this._lightboxPanX = 0;
    this._lightboxPanY = 0;
    this._lightboxDragging = false;
    this._lightboxDragStartX = 0;
    this._lightboxDragStartY = 0;
    this._lightboxPointers = {};
    this._lightboxPinchStartDistance = 0;
    this._lightboxPinchStartZoom = 1;
  }

  Widget.prototype._hasApi = function _hasApi() {
    return !!this.options.apiBase;
  };

  Widget.prototype._apiUrl = function _apiUrl(pathname) {
    var base = this.options.apiBase.replace(/\/$/, '');
    var clean = pathname.charAt(0) === '/' ? pathname : '/' + pathname;
    var joiner = clean.indexOf('?') === -1 ? '?' : '&';
    return base + clean + joiner + 'widgetId=' + encodeURIComponent(this.options.widgetId || 'default');
  };

  Widget.prototype._request = function _request(pathname, method, body) {
    var req = {
      method: method || 'GET',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }
    };
    if (body) req.body = JSON.stringify(body);

    return global.fetch(this._apiUrl(pathname), req).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () { return {}; }).then(function (payload) {
          throw new Error(payload.error || ('HTTP ' + res.status));
        });
      }
      return res.json();
    });
  };

  Widget.prototype._countIncomingMessages = function _countIncomingMessages(messages, startIndex) {
    var self = this;
    if (!Array.isArray(messages)) return 0;
    var start = Number(startIndex) > 0 ? Number(startIndex) : 0;
    return messages.slice(start).filter(function (msg) {
      return msg && msg.sender && msg.sender !== self.state.me.id;
    }).length;
  };

  Widget.prototype._applyConversations = function _applyConversations(nextConversations, opts) {
    var options = opts || {};
    var next = Array.isArray(nextConversations) ? nextConversations : [];
    var prev = Array.isArray(this.state.conversations) ? this.state.conversations : [];
    var prevById = prev.reduce(function (acc, convo) {
      if (convo && convo.id) acc[convo.id] = convo;
      return acc;
    }, {});
    var nextUnread = {};
    var oldUnread = this.state.unreadByConvo || {};
    var isInitialLoad = !!options.initialLoad;
    var self = this;
    var incomingNotice = null;

    next.forEach(function (convo) {
      if (!convo || !convo.id) return;
      var messages = Array.isArray(convo.messages) ? convo.messages : [];
      var previous = prevById[convo.id];
      var prevMessages = previous && Array.isArray(previous.messages) ? previous.messages : [];
      var unread = Number(oldUnread[convo.id]) || 0;
      var isActiveOpen = self.state.open && self.state.activeConvoId === convo.id;
      var incomingMessages = [];

      if (!isInitialLoad && messages.length > prevMessages.length && !isActiveOpen) {
        incomingMessages = messages.slice(prevMessages.length).filter(function (msg) {
          return msg && msg.sender && msg.sender !== self.state.me.id;
        });
        unread += incomingMessages.length;
      }
      if (!self.state.open && incomingMessages.length > 0) {
        var participants = Array.isArray(convo.participants) ? convo.participants : [];
        var directPeerId = participants.find(function (id) { return id !== self.state.me.id; }) || participants[0];
        var peer = self._getUser(directPeerId);
        var sender = incomingMessages[incomingMessages.length - 1].sender;
        var senderUser = self._getUser(sender);
        incomingNotice = {
          title: convo.isGroup
            ? (senderUser && senderUser.name ? senderUser.name : 'Nytt meddelande') + ' i ' + (convo.name || 'Grupp')
            : (peer && peer.name ? peer.name : 'Ny kontakt'),
          text: self._messagePreviewText(incomingMessages[incomingMessages.length - 1]) || 'Nytt meddelande'
        };
      }
      if (isActiveOpen) unread = 0;
      if (unread > 0) nextUnread[convo.id] = unread;
    });

    this.state.conversations = next;
    this.state.unreadByConvo = nextUnread;
    this._hasBootstrappedConversations = true;
    this._renderConversations();
    if (this.state.activeConvoId) this._renderChatFeed();
    this._renderLauncherUnread();
    if (incomingNotice) this._showIncomingToast(incomingNotice);
  };

  Widget.prototype._renderLauncherUnread = function _renderLauncherUnread() {
    if (!this._els.launcher) return;
    var total = Object.keys(this.state.unreadByConvo || {}).reduce(function (sum, key) {
      return sum + (Number((this.state.unreadByConvo || {})[key]) || 0);
    }.bind(this), 0);
    this._els.launcher.classList.toggle('has-unread', total > 0);
    this._els.launcher.setAttribute('aria-label', total > 0 ? ('Öppna chatt (' + total + ' olästa)') : 'Öppna chatt');
    var badge = this._els.launcher.querySelector('[data-el="launcher-unread"]');
    if (badge) badge.textContent = total > 99 ? '99+' : String(total);
  };

  Widget.prototype._markConversationRead = function _markConversationRead(convoId) {
    if (!convoId) return;
    if (!this.state.unreadByConvo || !this.state.unreadByConvo[convoId]) return;
    delete this.state.unreadByConvo[convoId];
    this._renderConversations();
    this._renderLauncherUnread();
  };

  Widget.prototype._startPolling = function _startPolling() {
    var self = this;
    if (!this._hasApi() || this._pollTimer) return;
    this._pollTimer = global.setInterval(function () {
      self._refreshConversations();
    }, 3000);
  };

  Widget.prototype._showIncomingToast = function _showIncomingToast(notice) {
    var toast = this._els && this._els.toast;
    if (!toast) return;
    if (global.matchMedia && global.matchMedia('(max-width: 768px)').matches) return;
    if (this._toastTimer) clearTimeout(this._toastTimer);
    var title = escapeHtml((notice && notice.title) || 'Nytt meddelande');
    var text = escapeHtml((notice && notice.text) || '');
    toast.innerHTML = '<div class="toast-title">' + title + '</div><div class="toast-text">' + text + '</div>';
    toast.classList.add('open');
    this._toastTimer = global.setTimeout(function () {
      toast.classList.remove('open');
    }, 3200);
  };

  Widget.prototype._bootstrap = function _bootstrap() {
    var self = this;
    if (!this._hasApi()) return Promise.resolve();

    return Promise.allSettled([
      this._request('/users', 'GET'),
      this._request('/conversations', 'GET')
    ]).then(function (results) {
      var usersResult = results[0];
      var convosResult = results[1];
      var usersRequestOk = usersResult && usersResult.status === 'fulfilled';
      var usersPayload = usersResult && usersResult.status === 'fulfilled' ? (usersResult.value || {}) : null;
      var convoPayload = convosResult && convosResult.status === 'fulfilled' ? (convosResult.value || {}) : null;

      if (usersPayload && usersPayload.me) self.state.me = usersPayload.me;
      if (usersPayload && Array.isArray(usersPayload.users)) self.state.users = usersPayload.users.map(normalizeUser);
      if (convoPayload && Array.isArray(convoPayload.conversations)) {
        self._applyConversations(convoPayload.conversations, { initialLoad: !self._hasBootstrappedConversations });
      } else {
        self._applyConversations([], { initialLoad: !self._hasBootstrappedConversations });
      }

      if (self.state.users.length > 0 || usersRequestOk) {
        self._renderContacts(self.state.users);
        if (self.state.activeConvoId) self._renderChatFeed();
        return;
      }

      return Promise.allSettled([
        self._request('/me', 'GET'),
        self._request('/people', 'GET')
      ]).then(function (fallbackResults) {
        var meResult = fallbackResults[0];
        var peopleResult = fallbackResults[1];
        var mePayload = meResult && meResult.status === 'fulfilled' ? (meResult.value || {}) : {};
        var peoplePayload = peopleResult && peopleResult.status === 'fulfilled' ? (peopleResult.value || {}) : {};
        var meUser = mePayload.user || null;
        if (meUser && meUser.id != null) {
          self.state.me = {
            id: String(meUser.id),
            name: String(meUser.name || meUser.username || 'Du')
          };
        }
        if (Array.isArray(peoplePayload.users)) {
          self.state.users = peoplePayload.users.map(normalizeUser);
        } else {
          self.state.users = [];
        }
      });
    }).catch(function (error) {
      console.error('MessengerWidget API bootstrap failed:', error);
      self.state.users = [];
    }).finally(function () {
      self._renderConversations();
      self._renderContacts(self.state.users);
      if (self.state.activeConvoId) self._renderChatFeed();
      self._renderLauncherUnread();
    });
  };

  Widget.prototype._refreshConversations = function _refreshConversations() {
    var self = this;
    if (!this._hasApi()) return Promise.resolve();

    return this._request('/conversations', 'GET').then(function (payload) {
      if (Array.isArray(payload.conversations)) {
        self._applyConversations(payload.conversations, { initialLoad: !self._hasBootstrappedConversations });
      }
    }).catch(function (error) {
      console.error('MessengerWidget refresh failed:', error);
    });
  };

  Widget.prototype.mount = function mount(target) {
    if (this._host) return this;
    var mountTarget = target || document.body;
    if (!mountTarget) return this;

    var host = document.createElement('div');
    host.style.position = this.options.fixed === false ? 'relative' : 'fixed';
    if (this.options.fixed !== false) {
      host.style.zIndex = String(this.options.zIndex);
      host.style.bottom = this.options.bottom + 'px';
      if (this.options.position === 'left') {
        host.style.left = this.options.sideOffset + 'px';
      } else {
        host.style.right = this.options.sideOffset + 'px';
      }
    } else {
      host.style.width = this.options.width + 'px';
      host.style.height = this.options.height + 'px';
      host.style.maxWidth = '100%';
      host.style.maxHeight = '100%';
    }

    var root = host.attachShadow({ mode: 'open' });
    root.innerHTML = this._template();

    mountTarget.appendChild(host);

    this._host = host;
    this._root = root;
    this._cacheElements();
    this._bindEvents();
    this._renderConversations();
    this._renderContacts(this.state.users);
    this._renderPendingFiles();
    this._bootstrap();
    this._startPolling();

    return this;
  };

  Widget.prototype.destroy = function destroy() {
    if (this._replyTimer) clearTimeout(this._replyTimer);
    if (this._pollTimer) clearInterval(this._pollTimer);
    if (this._toastTimer) clearTimeout(this._toastTimer);
    if (this._docKeydownHandler) document.removeEventListener('keydown', this._docKeydownHandler);
    if (this._docClickHandler) document.removeEventListener('click', this._docClickHandler);
    this._pollTimer = null;
    this._toastTimer = null;
    this._docKeydownHandler = null;
    this._docClickHandler = null;
    if (this._host && this._host.parentNode) this._host.parentNode.removeChild(this._host);
    this._host = null;
    this._root = null;
    this._els = {};
  };

  Widget.prototype._cacheElements = function _cacheElements() {
    var $ = this._root.querySelector.bind(this._root);
    this._els = {
      launcher: $('[data-el="launcher"]'),
      panel: $('[data-el="panel"]'),
      closeBtn: $('[data-el="close"]'),
      convoView: $('[data-el="view-convos"]'),
      searchView: $('[data-el="view-search"]'),
      chatView: $('[data-el="view-chat"]'),
      mainHeader: $('[data-el="main-header"]'),
      convoList: $('[data-el="convo-list"]'),
      contactList: $('[data-el="contact-list"]'),
      searchInput: $('[data-el="search-input"]'),
      activeName: $('[data-el="active-name"]'),
      activeStatus: $('[data-el="active-status"]'),
      activeAvatar: $('[data-el="active-avatar"]'),
      feed: $('[data-el="feed"]'),
      attachmentTray: $('[data-el="attachment-tray"]'),
      messageInput: $('[data-el="message-input"]'),
      sendBtn: $('[data-el="send"]'),
      emojiBtn: $('[data-el="emoji"]'),
      fileBtn: $('[data-el="file-btn"]'),
      fileInput: $('[data-el="file-input"]'),
      lightbox: $('[data-el="lightbox"]'),
      lightboxStage: $('[data-el="lightbox-stage"]'),
      lightboxImage: $('[data-el="lightbox-image"]'),
      lightboxCaption: $('[data-el="lightbox-caption"]'),
      lightboxClose: $('[data-el="lightbox-close"]'),
      backBtn: $('[data-el="back"]'),
      createGroup: $('[data-el="create-group"]')
      ,
      toast: $('[data-el="toast"]')
    };
  };

  Widget.prototype._bindEvents = function _bindEvents() {
    var self = this;

    if (this._els.launcher) {
      this._els.launcher.addEventListener('click', function () { self.toggle(); });
    }
    this._els.closeBtn.addEventListener('click', function () { self.toggle(false); });
    this._els.backBtn.addEventListener('click', function () { self._backToMain(); });
    this._els.createGroup.addEventListener('click', function () { self._createGroup(); });

    this._els.searchInput.addEventListener('focus', function () { self._openSearch(); });
    this._els.searchInput.addEventListener('input', function () { self._handleSearch(); });

    this._els.sendBtn.addEventListener('click', function () { self._sendMessage(); });
    this._els.emojiBtn.addEventListener('click', function () { self._addEmoji(); });
    this._els.fileBtn.addEventListener('click', function () { self._els.fileInput.click(); });
    this._els.fileInput.addEventListener('change', function (event) { self._handleFileUpload(event); });
    this._els.attachmentTray.addEventListener('click', function (event) {
      var removeBtn = event.target.closest('[data-remove-file-id]');
      if (!removeBtn) return;
      self._removePendingFile(removeBtn.getAttribute('data-remove-file-id'));
    });

    this._els.messageInput.addEventListener('input', function (event) {
      var el = event.target;
      el.style.height = '5px';
      el.style.height = el.scrollHeight + 'px';
    });

    this._els.messageInput.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        self._sendMessage();
      }
    });

    this._els.convoList.addEventListener('click', function (event) {
      var item = event.target.closest('[data-convo-id]');
      if (!item) return;
      self._openChat(item.getAttribute('data-convo-id'));
    });

    this._els.contactList.addEventListener('click', function (event) {
      var item = event.target.closest('[data-user-id]');
      if (!item) return;
      self._startDirectChat(item.getAttribute('data-user-id'));
    });

    this._els.feed.addEventListener('click', function (event) {
      var thumb = event.target.closest('[data-preview-src]');
      if (!thumb) return;
      self._openImagePreview(thumb.getAttribute('data-preview-src'), thumb.getAttribute('data-preview-name'));
    });

    this._els.lightbox.addEventListener('click', function (event) {
      if (event.target === self._els.lightbox || event.target === self._els.lightboxClose) self._closeImagePreview();
    });
    this._els.lightboxStage.addEventListener('wheel', function (event) {
      event.preventDefault();
      var nextZoom = Math.max(1, Math.min(6, self._lightboxZoom + (event.deltaY < 0 ? 0.2 : -0.2)));
      if (nextZoom === self._lightboxZoom) return;
      self._lightboxZoom = nextZoom;
      self._applyLightboxTransform();
    }, { passive: false });
    this._els.lightboxStage.addEventListener('pointerdown', function (event) {
      if (event.pointerType === 'mouse' && event.button !== 0) return;
      if (self._lightboxZoom <= 1) return;
      event.preventDefault();
      self._lightboxPointers[event.pointerId] = { x: event.clientX, y: event.clientY };
      var ids = Object.keys(self._lightboxPointers);
      if (ids.length === 2) {
        var a = self._lightboxPointers[ids[0]];
        var b = self._lightboxPointers[ids[1]];
        self._lightboxPinchStartDistance = Math.hypot(a.x - b.x, a.y - b.y) || 1;
        self._lightboxPinchStartZoom = self._lightboxZoom;
        self._lightboxDragging = false;
        self._els.lightboxStage.classList.remove('dragging');
      }
      if (ids.length > 1) return;
      self._lightboxDragging = true;
      self._lightboxDragStartX = event.clientX - self._lightboxPanX;
      self._lightboxDragStartY = event.clientY - self._lightboxPanY;
      self._els.lightboxStage.classList.add('dragging');
      if (self._els.lightboxStage.setPointerCapture) self._els.lightboxStage.setPointerCapture(event.pointerId);
    });
    this._els.lightboxStage.addEventListener('pointermove', function (event) {
      if (self._lightboxPointers[event.pointerId]) {
        self._lightboxPointers[event.pointerId].x = event.clientX;
        self._lightboxPointers[event.pointerId].y = event.clientY;
      }
      var ids = Object.keys(self._lightboxPointers);
      if (ids.length >= 2) {
        event.preventDefault();
        var a = self._lightboxPointers[ids[0]];
        var b = self._lightboxPointers[ids[1]];
        var distance = Math.hypot(a.x - b.x, a.y - b.y) || 1;
        var zoom = self._lightboxPinchStartZoom * (distance / (self._lightboxPinchStartDistance || 1));
        self._lightboxZoom = Math.max(1, Math.min(6, zoom));
        self._applyLightboxTransform();
        return;
      }
      if (!self._lightboxDragging) return;
      event.preventDefault();
      self._lightboxPanX = event.clientX - self._lightboxDragStartX;
      self._lightboxPanY = event.clientY - self._lightboxDragStartY;
      self._applyLightboxTransform();
    });
    this._els.lightboxStage.addEventListener('pointerup', function (event) {
      self._lightboxDragging = false;
      self._els.lightboxStage.classList.remove('dragging');
      delete self._lightboxPointers[event.pointerId];
      self._lightboxPinchStartDistance = 0;
      if (self._els.lightboxStage.releasePointerCapture) {
        try { self._els.lightboxStage.releasePointerCapture(event.pointerId); } catch (e) {}
      }
    });
    this._els.lightboxStage.addEventListener('pointercancel', function (event) {
      self._lightboxDragging = false;
      self._els.lightboxStage.classList.remove('dragging');
      delete self._lightboxPointers[event.pointerId];
      self._lightboxPinchStartDistance = 0;
      if (self._els.lightboxStage.releasePointerCapture) {
        try { self._els.lightboxStage.releasePointerCapture(event.pointerId); } catch (e) {}
      }
    });

    this._docKeydownHandler = function (event) {
      if (event.key === 'Escape') self._closeImagePreview();
    };
    document.addEventListener('keydown', this._docKeydownHandler);

    this._docClickHandler = function (event) {
      if (self.options.hideLauncher) return;
      if (!self._host || !self.state.open) return;
      if (self._host.contains(event.target)) return;
      self.toggle(false);
    };
    document.addEventListener('click', this._docClickHandler);
  };

  Widget.prototype.toggle = function toggle(forceState) {
    var open = typeof forceState === 'boolean' ? forceState : !this.state.open;
    this.state.open = open;
    this._els.panel.classList.toggle('open', open);
    if (open && this.state.activeConvoId == null) this._els.searchInput.focus();
  };

  Widget.prototype._openSearch = function _openSearch() {
    if (this.state.activeConvoId) return;
    this._els.convoView.classList.add('slide-left');
    this._els.convoView.classList.remove('active');
    this._els.searchView.classList.add('active');
    this._els.searchView.classList.remove('slide-right');
    this._renderContacts(this.state.users);
  };

  Widget.prototype._backToMain = function _backToMain() {
    this.state.activeConvoId = null;
    this.state.pendingFiles = [];
    this._els.mainHeader.style.display = 'block';
    this._els.searchInput.value = '';

    this._els.chatView.classList.remove('active');
    this._els.chatView.classList.add('slide-right');
    this._els.convoView.classList.remove('slide-left');
    this._els.convoView.classList.add('active');
    this._els.searchView.classList.remove('active');
    this._els.searchView.classList.add('slide-right');

    this._renderConversations();
    this._renderPendingFiles();
  };

  Widget.prototype._getUser = function _getUser(userId) {
    return this.state.users.find(function (u) { return u.id === userId; });
  };

  Widget.prototype._findDirectConversation = function _findDirectConversation(userId) {
    var meId = this.state.me && this.state.me.id ? this.state.me.id : '';
    return (this.state.conversations || []).find(function (c) {
      if (!c || c.isGroup) return false;
      var participants = Array.isArray(c.participants) ? c.participants : [];
      if (!participants.includes(userId)) return false;
      if (!meId) return true;
      if (participants.includes(meId)) return true;
      return participants.length === 1 && participants[0] === userId;
    }) || null;
  };

  Widget.prototype._avatar = function _avatar(user) {
    if (!user) return '<div class="avatar" style="background:#ddd">G</div>';
    var dot = user.online ? '<div class="online-dot"></div>' : '';
    return '<div class="avatar" style="background:' + user.color + '33; color:' + user.color + '">' + user.initials + dot + '</div>';
  };

  Widget.prototype._normalizeAttachments = function _normalizeAttachments(attachments) {
    if (!Array.isArray(attachments)) return [];
    return attachments.map(function (file, idx) {
      var type = String(file && file.type ? file.type : '');
      return {
        id: String(file && file.id ? file.id : 'att-' + idx + '-' + Date.now()),
        name: String(file && file.name ? file.name : 'Bilaga'),
        type: type,
        size: Number(file && file.size ? file.size : 0),
        url: String(file && file.url ? file.url : ''),
        kind: isImageType(type) ? 'image' : 'file'
      };
    }).filter(function (file) {
      return !!file.url;
    });
  };

  Widget.prototype._messagePreviewText = function _messagePreviewText(message) {
    var text = String(message && message.text ? message.text : '').trim();
    var attachments = this._normalizeAttachments(message && message.attachments);
    if (text) return text;
    if (!attachments.length) return '';
    var images = attachments.filter(function (file) { return file.kind === 'image'; }).length;
    if (images === attachments.length) return images > 1 ? '📷 ' + images + ' bilder' : '📷 Bild';
    if (images > 0) return '📎 ' + attachments.length + ' bilagor';
    return attachments.length > 1 ? '📎 ' + attachments.length + ' filer' : '📎 Fil';
  };

  Widget.prototype._renderAttachments = function _renderAttachments(attachments) {
    var files = this._normalizeAttachments(attachments);
    if (!files.length) return '';
    return '<div class="msg-attachments">' + files.map(function (file) {
      if (file.kind === 'image') {
        return '<button class="msg-image-btn" type="button" data-preview-src="' + escapeHtml(file.url) + '" data-preview-name="' + escapeHtml(file.name) + '">' +
          '<img class="msg-image-thumb" src="' + escapeHtml(file.url) + '" alt="' + escapeHtml(file.name) + '">' +
        '</button>';
      }
      return '<a class="file-attachment" href="' + escapeHtml(file.url) + '" download="' + escapeHtml(file.name) + '">' +
        '📎 ' + escapeHtml(file.name) + ' (' + formatBytes(file.size) + ')' +
      '</a>';
    }).join('') + '</div>';
  };

  Widget.prototype._renderPendingFiles = function _renderPendingFiles() {
    var files = this.state.pendingFiles || [];
    if (!files.length) {
      this._els.attachmentTray.innerHTML = '';
      this._els.attachmentTray.style.display = 'none';
      return;
    }
    this._els.attachmentTray.style.display = 'flex';
    this._els.attachmentTray.innerHTML = files.map(function (file) {
      var preview = file.kind === 'image'
        ? '<img class="pending-thumb" src="' + escapeHtml(file.url) + '" alt="' + escapeHtml(file.name) + '">'
        : '<div class="pending-file-icon">📎</div>';
      return '<div class="pending-item">' +
        preview +
        '<div class="pending-meta">' +
          '<div class="pending-name">' + escapeHtml(file.name) + '</div>' +
          '<div class="pending-size">' + formatBytes(file.size) + '</div>' +
        '</div>' +
        '<button type="button" class="pending-remove" data-remove-file-id="' + escapeHtml(file.id) + '" aria-label="Ta bort fil">✕</button>' +
      '</div>';
    }).join('');
  };

  Widget.prototype._renderConversations = function _renderConversations() {
    var self = this;
    var list = this._els.convoList;
    var convos = Array.isArray(this.state.conversations) ? this.state.conversations : [];
    list.innerHTML = '';

    if (!convos.length) {
      list.innerHTML = '<div class="empty">Inga meddelanden än.</div>';
      return;
    }

    convos.slice().reverse().forEach(function (c) {
      var messages = Array.isArray(c && c.messages) ? c.messages : [];
      var participants = Array.isArray(c && c.participants) ? c.participants : [];
      var last = messages[messages.length - 1] || { sender: '', text: '', time: '' };
      var directPeerId = participants.find(function (id) { return id !== self.state.me.id; }) || participants[0];
      var peer = self._getUser(directPeerId);
      var title = c.isGroup ? c.name : (peer ? peer.name : 'Okänd kontakt');
      var avatar = c.isGroup ? '<div class="avatar" style="background:#e4e6eb">👥</div>' : self._avatar(peer);
      var prefix = last.sender === self.state.me.id ? 'Du: ' : '';
      var previewText = self._messagePreviewText(last);
      var unreadCount = Number((self.state.unreadByConvo || {})[c.id]) || 0;
      var unreadHtml = unreadCount > 0 ? '<div class="unread-pill">' + (unreadCount > 99 ? '99+' : unreadCount) + '</div>' : '';
      var unreadClass = unreadCount > 0 ? ' has-unread' : '';

      list.insertAdjacentHTML(
        'beforeend',
        '<div class="list-item' + unreadClass + '" data-convo-id="' + c.id + '">' +
          avatar +
          '<div class="item-info">' +
            '<div class="item-top">' +
              '<div class="item-name">' + escapeHtml(title) + '</div>' +
              '<div class="item-meta"><div class="item-time">' + escapeHtml(last.time || '') + '</div>' + unreadHtml + '</div>' +
            '</div>' +
            '<div class="item-preview">' + escapeHtml(prefix + previewText) + '</div>' +
          '</div>' +
        '</div>'
      );
    });
  };

  Widget.prototype._renderContacts = function _renderContacts(users) {
    var self = this;
    this._els.contactList.innerHTML = '';
    if (!users || !users.length) {
      this._els.contactList.innerHTML = '<div class="empty">Inga användare hittades.</div>';
      return;
    }
    users.forEach(function (u) {
      var convo = self._findDirectConversation(u.id);
      var messages = convo && Array.isArray(convo.messages) ? convo.messages : [];
      var last = messages[messages.length - 1] || null;
      var previewText = last ? self._messagePreviewText(last) : 'Starta en konversation';
      var unreadCount = convo ? (Number((self.state.unreadByConvo || {})[convo.id]) || 0) : 0;
      var unreadHtml = unreadCount > 0 ? '<div class="unread-pill">' + (unreadCount > 99 ? '99+' : unreadCount) + '</div>' : '';
      self._els.contactList.insertAdjacentHTML(
        'beforeend',
        '<div class="list-item" data-user-id="' + u.id + '">' +
          self._avatar(u) +
          '<div class="item-info">' +
            '<div class="item-top">' +
              '<div class="item-name">' + escapeHtml(u.name) + '</div>' +
              '<div class="item-meta">' +
                '<div class="item-time">' + escapeHtml((last && last.time) || '') + '</div>' +
                unreadHtml +
              '</div>' +
            '</div>' +
            '<div class="item-preview">' + escapeHtml(previewText) + '</div>' +
          '</div>' +
        '</div>'
      );
    });
  };

  Widget.prototype._openChat = function _openChat(convoId) {
    this.state.activeConvoId = convoId;
    this._els.searchInput.value = '';
    this._els.mainHeader.style.display = 'none';

    this._els.convoView.classList.add('slide-left');
    this._els.searchView.classList.add('slide-left');
    this._els.chatView.classList.add('active');
    this._els.chatView.classList.remove('slide-right');

    this._markConversationRead(convoId);
    this._renderChatFeed();
    this._renderPendingFiles();
  };

  Widget.prototype._renderChatFeed = function _renderChatFeed() {
    var self = this;
    var convo = this.state.conversations.find(function (c) { return c.id === self.state.activeConvoId; });
    if (!convo) return;

    var participants = Array.isArray(convo.participants) ? convo.participants : [];
    var directPeerId = participants.find(function (id) { return id !== self.state.me.id; }) || participants[0];
    var peer = this._getUser(directPeerId);
    var title = convo.isGroup ? convo.name : (peer ? peer.name : 'Okänd kontakt');
    var avatar = convo.isGroup ? '<div class="avatar" style="background:#e4e6eb">👥</div>' : this._avatar(peer);
    var status = convo.isGroup
      ? participants.length + ' medlemmar'
      : ((peer && peer.online) ? 'Aktiv nu' : 'Offline');

    this._els.activeName.textContent = title;
    this._els.activeStatus.textContent = status;
    this._els.activeAvatar.innerHTML = avatar;

    this._els.feed.innerHTML = '';
    var messages = Array.isArray(convo.messages) ? convo.messages : [];
    messages.forEach(function (m) {
      var mine = m.sender === self.state.me.id;
      var senderName = !mine && convo.isGroup ? (self._getUser(m.sender) || {}).name || 'Okänd' : '';
      var text = String(m && m.text ? m.text : '');
      var textHtml = text ? '<div class="msg-bubble">' + escapeHtml(text) + '</div>' : '';
      var attachmentsHtml = self._renderAttachments(m.attachments);
      self._els.feed.insertAdjacentHTML(
        'beforeend',
        '<div class="message ' + (mine ? 'msg-mine' : 'msg-theirs') + '">' +
          (senderName ? '<div class="msg-sender">' + escapeHtml(senderName) + '</div>' : '') +
          textHtml +
          attachmentsHtml +
          '<div class="msg-time">' + escapeHtml(m.time || '') + '</div>' +
        '</div>'
      );
    });

    this._els.feed.scrollTop = this._els.feed.scrollHeight;
  };

  Widget.prototype._handleSearch = function _handleSearch() {
    var value = this._els.searchInput.value.toLowerCase();
    if (!value && this._els.searchView.classList.contains('active')) {
      this._renderContacts(this.state.users);
      return;
    }
    if (value && !this._els.searchView.classList.contains('active')) this._openSearch();

    var filtered = this.state.users.filter(function (u) {
      return u.name.toLowerCase().indexOf(value) !== -1;
    });
    this._renderContacts(filtered);
  };

  Widget.prototype._startDirectChat = function _startDirectChat(userId) {
    var self = this;
    if (this._hasApi()) {
      this._request('/conversations/direct', 'POST', { userId: userId }).then(function (payload) {
        if (payload.conversation) {
          var existing = self.state.conversations.find(function (c) { return c.id === payload.conversation.id; });
          if (!existing) self.state.conversations.push(payload.conversation);
          self._renderConversations();
          self._openChat(payload.conversation.id);
          self._refreshConversations();
        }
      }).catch(function (error) {
        console.error('Could not create direct chat:', error);
      });
      return;
    }

    var convo = this.state.conversations.find(function (c) {
      return !c.isGroup && c.participants[0] === userId;
    });

    if (!convo) {
      convo = {
        id: 'c' + Date.now(),
        isGroup: false,
        participants: [userId],
        messages: []
      };
      this.state.conversations.push(convo);
    }

    this._openChat(convo.id);
  };

  Widget.prototype._createGroup = function _createGroup() {
    var self = this;
    var name = global.prompt('Ange namn på gruppen:');
    if (!name) return;

    if (this._hasApi()) {
      this._request('/conversations/group', 'POST', {
        name: name,
        participantIds: this.state.users.map(function (u) { return u.id; })
      }).then(function (payload) {
        if (payload.conversation) {
          self.state.conversations.push(payload.conversation);
          self._renderConversations();
          self._openChat(payload.conversation.id);
        }
      }).catch(function (error) {
        console.error('Could not create group:', error);
      });
      return;
    }

    var convo = {
      id: 'c' + Date.now(),
      isGroup: true,
      name: name,
      participants: this.state.users.map(function (u) { return u.id; }),
      messages: [{ sender: this.state.me.id, text: 'Skapade gruppen', time: nowTime() }]
    };

    this.state.conversations.push(convo);
    this._openChat(convo.id);
  };

  Widget.prototype._sendMessage = function _sendMessage(textParam) {
    var text = typeof textParam === 'string' ? textParam : this._els.messageInput.value.trim();
    var attachments = (this.state.pendingFiles || []).slice();
    if ((!text && attachments.length === 0) || !this.state.activeConvoId) return;

    var convo = this.state.conversations.find(function (c) {
      return c.id === this.state.activeConvoId;
    }, this);

    if (!convo) return;

    if (this._hasApi()) {
      var self = this;
      this._request('/conversations/' + encodeURIComponent(convo.id) + '/messages', 'POST', {
        sender: this.state.me.id,
        text: text,
        attachments: attachments
      }).then(function () {
        self._els.messageInput.value = '';
        self._els.messageInput.style.height = 'auto';
        self.state.pendingFiles = [];
        self._renderPendingFiles();
        self._refreshConversations();
      }).catch(function (error) {
        console.error('Could not send message:', error);
      });
      return;
    }

    convo.messages.push({ sender: this.state.me.id, text: text, attachments: attachments, time: nowTime() });

    this._els.messageInput.value = '';
    this._els.messageInput.style.height = 'auto';
    this.state.pendingFiles = [];
    this._renderPendingFiles();
    this._renderChatFeed();

    if (this._replyTimer) clearTimeout(this._replyTimer);
    if (!convo.isGroup || Math.random() > 0.5) {
      var replySelf = this;
      var replierId = convo.isGroup
        ? convo.participants[Math.floor(Math.random() * convo.participants.length)]
        : convo.participants[0];

      this._replyTimer = setTimeout(function () {
        convo.messages.push({ sender: replierId, text: 'Visst, jag förstår! 👍', time: nowTime() });
        var isActiveOpen = replySelf.state.open && replySelf.state.activeConvoId === convo.id;
        if (isActiveOpen) {
          replySelf._renderChatFeed();
        } else {
          replySelf.state.unreadByConvo[convo.id] = (Number(replySelf.state.unreadByConvo[convo.id]) || 0) + 1;
          replySelf._renderConversations();
          replySelf._renderLauncherUnread();
        }
      }, 1200);
    }
  };

  Widget.prototype._addEmoji = function _addEmoji() {
    var emojis = ['😂', '❤️', '👍', '🔥', '😊', '🎉'];
    var e = emojis[Math.floor(Math.random() * emojis.length)];
    this._els.messageInput.value += e;
    this._els.messageInput.focus();
  };

  Widget.prototype._handleFileUpload = function _handleFileUpload(event) {
    var self = this;
    var fileList = event.target.files ? Array.prototype.slice.call(event.target.files) : [];
    if (!fileList.length) return;

    Promise.all(fileList.map(function (file) {
      if (file.size > 5 * 1024 * 1024) {
        return Promise.resolve(null);
      }
      return new Promise(function (resolve) {
        var reader = new FileReader();
        reader.onload = function () {
          resolve({
            id: id('att'),
            name: file.name,
            type: file.type || 'application/octet-stream',
            size: file.size || 0,
            url: String(reader.result || ''),
            kind: isImageType(file.type) ? 'image' : 'file'
          });
        };
        reader.onerror = function () { resolve(null); };
        reader.readAsDataURL(file);
      });
    })).then(function (items) {
      var added = items.filter(Boolean);
      if (!added.length) {
        global.alert('Filen är för stor eller kunde inte läsas. Max 5 MB per fil.');
        return;
      }
      self.state.pendingFiles = self.state.pendingFiles.concat(added);
      self._renderPendingFiles();
    });
    event.target.value = '';
  };

  Widget.prototype._removePendingFile = function _removePendingFile(fileId) {
    this.state.pendingFiles = (this.state.pendingFiles || []).filter(function (file) {
      return file.id !== fileId;
    });
    this._renderPendingFiles();
  };

  Widget.prototype._openImagePreview = function _openImagePreview(src, name) {
    if (!src) return;
    this._resetLightboxTransform();
    var self = this;
    this._els.lightboxImage.onload = function () {
      self._applyLightboxTransform();
    };
    this._els.lightboxImage.src = src;
    this._els.lightboxImage.alt = name || 'Bild';
    this._els.lightboxCaption.textContent = name || '';
    this._els.lightbox.classList.add('open');
  };

  Widget.prototype._closeImagePreview = function _closeImagePreview() {
    this._els.lightbox.classList.remove('open');
    this._resetLightboxTransform();
    this._els.lightboxImage.src = '';
    this._els.lightboxCaption.textContent = '';
  };

  Widget.prototype._resetLightboxTransform = function _resetLightboxTransform() {
    this._lightboxZoom = 1;
    this._lightboxPanX = 0;
    this._lightboxPanY = 0;
    this._lightboxDragging = false;
    this._lightboxPointers = {};
    this._lightboxPinchStartDistance = 0;
    this._lightboxPinchStartZoom = 1;
    if (this._els.lightboxStage) this._els.lightboxStage.classList.remove('dragging', 'zoomed');
    this._applyLightboxTransform();
  };

  Widget.prototype._lightboxBaseSize = function _lightboxBaseSize() {
    var image = this._els.lightboxImage;
    var stage = this._els.lightboxStage;
    if (!image || !stage) return { width: 0, height: 0 };
    var naturalW = Number(image.naturalWidth) || 0;
    var naturalH = Number(image.naturalHeight) || 0;
    var stageW = Number(stage.clientWidth) || 0;
    var stageH = Number(stage.clientHeight) || 0;
    if (!naturalW || !naturalH || !stageW || !stageH) {
      return { width: Number(image.clientWidth) || 0, height: Number(image.clientHeight) || 0 };
    }
    var fit = Math.min(stageW / naturalW, stageH / naturalH);
    return {
      width: naturalW * fit,
      height: naturalH * fit
    };
  };

  Widget.prototype._applyLightboxTransform = function _applyLightboxTransform() {
    var image = this._els.lightboxImage;
    var stage = this._els.lightboxStage;
    if (!image || !stage) return;
    var base = this._lightboxBaseSize();
    if (this._lightboxZoom <= 1) {
      this._lightboxPanX = 0;
      this._lightboxPanY = 0;
    } else {
      var maxX = Math.max(0, ((base.width * this._lightboxZoom) - stage.clientWidth) / 2);
      var maxY = Math.max(0, ((base.height * this._lightboxZoom) - stage.clientHeight) / 2);
      this._lightboxPanX = Math.max(-maxX, Math.min(maxX, this._lightboxPanX));
      this._lightboxPanY = Math.max(-maxY, Math.min(maxY, this._lightboxPanY));
    }
    image.style.transform = 'translate(' + this._lightboxPanX + 'px,' + this._lightboxPanY + 'px) scale(' + this._lightboxZoom + ')';
    stage.classList.toggle('zoomed', this._lightboxZoom > 1);
  };

  Widget.prototype._template = function _template() {
    var panelSide = this.options.position === 'left' ? 'left:0;' : 'right:0;';
    var panelBottom = this.options.hideLauncher ? '0px' : (this.options.launcherSize + 16) + 'px';
    var launcherHtml = this.options.hideLauncher
      ? ''
      : '  <div class="launcher" data-el="launcher" aria-label="Öppna chatt">' +
        '    <span class="launcher-unread" data-el="launcher-unread">0</span>' +
        '    <svg viewBox="0 0 24 24"><path d="M12 2C6.477 2 2 6.145 2 11.259c0 2.913 1.474 5.503 3.765 7.184V22l3.435-1.897c.884.246 1.815.38 2.8.38 5.523 0 10-4.145 10-9.224S17.523 2 12 2z"/></svg>' +
        '  </div>';
    return [
      '<style>',
      ':host{all:initial;}',
      '.wrap{position:relative;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}',
      '.launcher{width:' + this.options.launcherSize + 'px;height:' + this.options.launcherSize + 'px;border-radius:50%;background:' + this.options.primaryColor + ';box-shadow:0 4px 12px rgba(0,0,0,.2);display:flex;align-items:center;justify-content:center;cursor:pointer;}',
      '.launcher{position:relative;}',
      '.launcher-unread{display:none;position:absolute;top:-5px;right:-4px;min-width:18px;height:18px;padding:0 5px;border-radius:999px;background:#e11d48;color:#fff;font-size:.68rem;font-weight:700;line-height:18px;text-align:center;box-shadow:0 0 0 2px #fff;}',
      '.launcher.has-unread .launcher-unread{display:block;}',
      '.launcher svg{width:32px;height:32px;fill:#fff;}',
      '.toast{position:absolute;right:0;bottom:' + (this.options.launcherSize + 28) + 'px;max-width:280px;background:#111827;color:#fff;border-radius:12px;padding:10px 12px;box-shadow:0 12px 24px rgba(0,0,0,.28);opacity:0;transform:translateY(6px);pointer-events:none;transition:all .2s ease;}',
      '.toast.open{opacity:1;transform:translateY(0);}',
      '.toast-title{font-size:.78rem;font-weight:700;line-height:1.3;margin-bottom:2px;}',
      '.toast-text{font-size:.76rem;line-height:1.3;color:#d1d5db;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.panel{position:absolute;bottom:' + panelBottom + ';' + panelSide + 'width:' + this.options.width + 'px;height:' + this.options.height + 'px;max-height:calc(100vh - 120px);background:#fff;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.15);overflow:hidden;display:flex;flex-direction:column;opacity:0;pointer-events:none;transform:translateY(20px);transition:all .25s ease;}',
      '.panel.open{opacity:1;pointer-events:auto;transform:translateY(0);}',
      '.header{padding:12px 16px;border-bottom:1px solid #e4e6eb;display:flex;align-items:center;justify-content:space-between;background:#fff;}',
      '.header h2{margin:0;font-size:1.1rem;color:#050505;}',
      '.icon-btn{background:none;border:none;cursor:pointer;padding:8px;border-radius:50%;display:flex;align-items:center;justify-content:center;}',
      '.icon-btn:hover{background:#f0f2f5;}',
      '.icon-btn svg{width:20px;height:20px;fill:' + this.options.primaryColor + ';}',
      '.search{padding:8px 16px;position:relative;border-bottom:1px solid #f0f2f5;}',
      '.search input{width:100%;border:0;background:#f0f2f5;border-radius:20px;padding:10px 12px;font-size:.95rem;outline:none;}',
      '.view-container{flex:1;position:relative;overflow:hidden;background:#fff;}',
      '.view{position:absolute;inset:0;display:flex;flex-direction:column;background:#fff;transition:transform .25s ease;}',
      '.view.active{transform:translateX(0);z-index:10;}',
      '.view.slide-left{transform:translateX(-100%);}',
      '.view.slide-right{transform:translateX(100%);}',
      '.scroll{overflow-y:auto;flex:1;}',
      '.list-item{display:flex;align-items:center;padding:12px 16px;cursor:pointer;}',
      '.list-item:hover{background:#f0f2f5;}',
      '.avatar{width:44px;height:44px;border-radius:50%;margin-right:12px;display:flex;align-items:center;justify-content:center;font-weight:700;position:relative;}',
      '.online-dot{position:absolute;bottom:0;right:0;width:12px;height:12px;border-radius:50%;background:#31a24c;border:2px solid #fff;}',
      '.item-info{flex:1;min-width:0;}',
      '.item-top{display:flex;justify-content:space-between;gap:8px;}',
      '.item-meta{display:flex;align-items:center;gap:6px;}',
      '.item-name{font-size:.94rem;font-weight:600;color:#050505;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.item-time{font-size:.74rem;color:#65676b;}',
      '.item-preview{font-size:.84rem;color:#65676b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;}',
      '.list-item.has-unread .item-preview{font-weight:700;color:#111827;}',
      '.unread-pill{background:#0ea5e9;color:#fff;font-size:.68rem;font-weight:700;line-height:1;padding:4px 6px;border-radius:999px;}',
      '.chat-header{padding:12px;border-bottom:1px solid #e4e6eb;display:flex;align-items:center;}',
      '.feed{padding:16px;display:flex;flex-direction:column;gap:8px;}',
      '.message{display:flex;max-width:78%;flex-direction:column;}',
      '.msg-mine{align-self:flex-end;align-items:flex-end;}',
      '.msg-theirs{align-self:flex-start;align-items:flex-start;}',
      '.msg-bubble{padding:10px 14px;border-radius:18px;font-size:.95rem;line-height:1.4;word-break:break-word;}',
      '.msg-mine .msg-bubble{background:' + this.options.primaryColor + ';color:#fff;border-bottom-right-radius:4px;}',
      '.msg-theirs .msg-bubble{background:#e4e6eb;color:#050505;border-bottom-left-radius:4px;}',
      '.msg-sender{font-size:.7rem;color:#65676b;margin-bottom:4px;margin-left:4px;}',
      '.msg-time{font-size:.7rem;color:#65676b;margin-top:4px;}',
      '.msg-attachments{display:flex;flex-wrap:wrap;gap:6px;max-width:250px;}',
      '.msg-image-btn{padding:0;border:0;background:transparent;cursor:pointer;}',
      '.msg-image-thumb{width:86px;height:86px;object-fit:cover;border-radius:10px;display:block;border:1px solid #d1d5db;}',
      '.input-area{padding:12px;border-top:1px solid #e4e6eb;display:flex;align-items:flex-end;gap:8px;padding-bottom:calc(12px + env(safe-area-inset-bottom, 0px));}',
      '.attachment-tray{display:none;gap:6px;overflow:auto;padding:8px 12px 0;border-top:1px solid #f3f4f6;}',
      '.pending-item{display:flex;align-items:center;gap:8px;background:#f3f4f6;border-radius:10px;padding:6px 8px;min-width:160px;max-width:240px;}',
      '.pending-thumb{width:34px;height:34px;border-radius:8px;object-fit:cover;flex:0 0 auto;}',
      '.pending-file-icon{width:34px;height:34px;border-radius:8px;background:#e5e7eb;display:flex;align-items:center;justify-content:center;flex:0 0 auto;}',
      '.pending-meta{min-width:0;}',
      '.pending-name{font-size:.75rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.pending-size{font-size:.68rem;color:#6b7280;}',
      '.pending-remove{border:0;background:transparent;cursor:pointer;color:#6b7280;font-size:.9rem;line-height:1;}',
      '.input-wrap{flex:1;background:#f0f2f5;border-radius:20px;display:flex;align-items:center;padding:8px 12px;}',
      '.input-wrap textarea{flex:1;border:none;background:transparent;outline:none;resize:none;max-height:80px;font-size:.95rem;padding:0;margin-right:8px;}',
      '.group-btn{margin:12px 16px;padding:10px;border-radius:8px;background:#e7f3ff;color:' + this.options.primaryColor + ';font-weight:600;text-align:center;cursor:pointer;}',
      '.label{padding:0 16px 8px;font-weight:600;color:#65676b;font-size:.84rem;}',
      '.file-attachment{display:inline-flex;background:#f0f2f5;padding:8px 10px;border-radius:8px;font-size:.85rem;color:#111827;text-decoration:none;}',
      '.lightbox{position:fixed;inset:0;background:rgba(0,0,0,.78);z-index:2147483647;display:none;align-items:center;justify-content:center;padding:16px;padding-top:calc(16px + env(safe-area-inset-top, 0px));padding-bottom:calc(16px + env(safe-area-inset-bottom, 0px));}',
      '.lightbox.open{display:flex;}',
      '.lightbox-inner{max-width:100%;max-height:100%;display:flex;flex-direction:column;gap:8px;align-items:center;}',
      '.lightbox-stage{width:min(92vw,920px);height:min(82vh,820px);background:#030712;border-radius:12px;overflow:hidden;display:flex;align-items:center;justify-content:center;touch-action:none;cursor:default;}',
      '.lightbox-stage.zoomed{cursor:grab;}',
      '.lightbox-stage.dragging{cursor:grabbing;}',
      '.lightbox-img{max-width:100%;max-height:100%;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.45);transform-origin:center center;will-change:transform;user-select:none;-webkit-user-drag:none;}',
      '.lightbox-caption{color:#fff;font-size:.85rem;text-align:center;word-break:break-word;}',
      '.lightbox-close{position:absolute;top:calc(10px + env(safe-area-inset-top, 0px));right:10px;font-size:1.2rem;color:#fff;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.25);border-radius:999px;width:34px;height:34px;cursor:pointer;}',
      '.empty{padding:18px;color:#65676b;text-align:center;}',
      '@media (max-width:768px){.panel{position:fixed;left:0;right:0;bottom:0;width:100vw;height:100dvh;max-height:100dvh;border-radius:0;}.toast{display:none;}.search{padding:8px 12px;}.header{padding:10px 12px;}.list-item{padding:10px 12px;}.chat-header{padding:10px;}}',
      '</style>',
      '<div class="wrap">',
      '  <div class="toast" data-el="toast"></div>',
      launcherHtml,
      '  <div class="panel" data-el="panel">',
      '    <div data-el="main-header">',
      '      <div class="header">',
      '        <h2>' + this.options.title + '</h2>',
      '        <button class="icon-btn" data-el="close" aria-label="Stäng"><svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>',
      '      </div>',
      '      <div class="search"><input type="text" data-el="search-input" placeholder="Sök eller starta ny chatt..."></div>',
      '    </div>',
      '    <div class="view-container">',
      '      <div class="view active scroll" data-el="view-convos"><div data-el="convo-list"></div></div>',
      '      <div class="view slide-right scroll" data-el="view-search">',
      '        <div class="group-btn" data-el="create-group">+ Skapa ny grupp</div>',
      '        <div class="label">Kontakter</div>',
      '        <div data-el="contact-list"></div>',
      '      </div>',
      '      <div class="view slide-right" data-el="view-chat">',
      '        <div class="chat-header">',
      '          <button class="icon-btn" data-el="back" aria-label="Tillbaka"><svg viewBox="0 0 24 24"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg></button>',
      '          <div data-el="active-avatar"></div>',
      '          <div class="item-info" style="margin-left:8px;">',
      '            <div class="item-name" data-el="active-name">Namn</div>',
      '            <div class="item-time" data-el="active-status">Aktiv nu</div>',
      '          </div>',
      '        </div>',
      '        <div class="feed scroll" data-el="feed"></div>',
      '        <div class="attachment-tray" data-el="attachment-tray"></div>',
      '        <div class="input-area">',
      '          <input type="file" data-el="file-input" id="' + this._inputId + '" style="display:none" multiple>',
      '          <button class="icon-btn" data-el="file-btn" aria-label="Bifoga">📎</button>',
      '          <div class="input-wrap">',
      '            <textarea rows="1" data-el="message-input" placeholder="Skriv ett meddelande..."></textarea>',
      '            <button class="icon-btn" data-el="emoji" aria-label="Emoji">😊</button>',
      '          </div>',
      '          <button class="icon-btn" data-el="send" aria-label="Skicka"><svg viewBox="0 0 24 24"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg></button>',
      '        </div>',
      '      </div>',
      '    </div>',
      '  </div>',
      '  <div class="lightbox" data-el="lightbox">',
      '    <button class="lightbox-close" type="button" data-el="lightbox-close" aria-label="Stäng bild">✕</button>',
      '    <div class="lightbox-inner">',
      '      <div class="lightbox-stage" data-el="lightbox-stage">',
      '        <img class="lightbox-img" data-el="lightbox-image" alt="Bildpreview" draggable="false">',
      '      </div>',
      '      <div class="lightbox-caption" data-el="lightbox-caption"></div>',
      '    </div>',
      '  </div>',
      '</div>'
    ].join('');
  };

  function fromDataset(script) {
    if (!script) return {};
    var opts = {};
    var inferredApiBase = '';
    try {
      inferredApiBase = new URL(script.src, global.location.href).origin + '/api';
    } catch (e) {
      inferredApiBase = '';
    }
    if (script.dataset.title) opts.title = script.dataset.title;
    if (script.dataset.primaryColor) opts.primaryColor = script.dataset.primaryColor;
    if (script.dataset.position === 'left' || script.dataset.position === 'right') opts.position = script.dataset.position;
    if (script.dataset.bottom) opts.bottom = toFiniteNumber(script.dataset.bottom, DEFAULTS.bottom);
    if (script.dataset.sideOffset) opts.sideOffset = toFiniteNumber(script.dataset.sideOffset, DEFAULTS.sideOffset);
    if (script.dataset.width) opts.width = toFiniteNumber(script.dataset.width, DEFAULTS.width);
    if (script.dataset.height) opts.height = toFiniteNumber(script.dataset.height, DEFAULTS.height);
    if (script.dataset.launcherSize) opts.launcherSize = toFiniteNumber(script.dataset.launcherSize, DEFAULTS.launcherSize);
    if (script.dataset.widgetId) opts.widgetId = script.dataset.widgetId;
    if (script.dataset.apiBase) {
      opts.apiBase = script.dataset.apiBase;
    } else if (inferredApiBase) {
      opts.apiBase = inferredApiBase;
    }
    return opts;
  }

  global.MessengerWidget = {
    init: function init(options) {
      var instance = new Widget(options || {});
      instance.mount((options || {}).target || document.body);
      return instance;
    },
    version: '1.1.0'
  };

  var current = document.currentScript;
  if (current && current.dataset.autoInit !== 'false') {
    global.__messengerWidget = global.MessengerWidget.init(fromDataset(current));
  }
})(window);
