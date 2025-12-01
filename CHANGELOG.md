# 📝 Changelog

All notable changes to StudyFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Email notifications system
- Video/audio call integration
- Admin dashboard
- Theme customization (blue, green, dark modes)

---

## [1.16.0] - 2025-12-01

### Added
- **🤖 AI Study Assistant**
  - OpenAI GPT-4o-mini integration for intelligent study help
  - Generate quiz questions from note content
  - Summarize long documents into key points
  - Explain complex topics in simple terms
  - Create comprehensive study guides
  - Interactive Q&A with context-aware responses
  - Markdown and math rendering for AI responses
  - Token usage tracking for cost monitoring
  - Configuration via environment variables
  - New routes: `/api/ai-assist` and `/api/ai-chat`
  - Comprehensive setup guide: `AI_ASSISTANT_GUIDE.md`
  - Example environment configuration: `.env.example`

### Changed
- Updated `requirements.txt` to include `openai==1.54.5`
- Enhanced `config.py` with AI configuration options
- Updated README with AI features section
- Added AI assistant panel to note viewing page

### Documentation
- Created `AI_ASSISTANT_GUIDE.md` with setup and usage instructions
- Created `.env.example` for environment variable configuration
- Added API endpoint documentation for AI features

---

## [1.15.0] - 2025-12-01

### Added
- **👤 User Profiles & Settings**
  - Public user profile pages with avatar, bio, and stats
  - Avatar upload with image preview
  - Profile statistics dashboard:
    * Total sessions created/joined
    * Messages sent
    * Notes created
    * Study streak tracking
  - Recent activity display (sessions & public notes)
  - Edit profile page with avatar upload
  - Settings page for preferences:
    * Email notification toggles
    * Session reminder preferences
    * Message notification settings
    * Theme selection (purple/blue/green/dark)
    * Privacy information
  - Profile link in navbar (click username)
  - Settings icon in navigation

### Technical
- New database columns on `users` table:
  * `avatar_filename`: Store uploaded avatar
  * `bio`: User biography text
  * `last_login`: Track last login timestamp
- New tables:
  * `user_settings`: Notification preferences, theme, language, timezone
  * `user_stats`: Activity tracking (sessions, messages, notes, study streak)
- Routes:
  * `/profile/<user_id>`: View user profile
  * `/profile/edit`: Edit own profile with avatar upload
  * `/settings`: User preferences and settings
  * `/uploads/avatars/<filename>`: Serve avatar images
- Avatar storage: `uploads/avatars/` directory
- Automatic stats initialization for existing users
- Migration script: `migrate_profiles.py`

### UI/UX
- Profile avatar display (150px circular)
- Avatar placeholder with gradient background
- Profile stats cards with color-coded icons
- Activity sections for recent sessions and notes
- Avatar upload with live preview
- Clean settings interface with toggle switches
- Mobile-responsive profile and settings pages
- Privacy information display

---

## [1.14.0] - 2025-12-01

### Added
- **🎴 Flashcard System with Spaced Repetition (SM-2 Algorithm)**
  - Create flashcard decks linked to sessions or standalone
  - Add cards with question/answer format
  - Study mode with 3D flip animation
  - SM-2 spaced repetition algorithm for optimal learning
  - Quality rating system (Forgot, Hard, Good, Easy)
  - Automatic review scheduling based on performance
  - Track learning progress per user
  - Public/private deck visibility
  - Beautiful card grid layout
  - Mobile-responsive study interface
  - Completion screen with statistics
  - Keyboard shortcuts (Space to flip)

### Technical
- New database tables:
  * `flashcard_decks`: Deck metadata (title, description, session link, visibility)
  * `flashcards`: Individual cards (question/answer pairs)
  * `flashcard_progress`: SM-2 algorithm tracking (easiness factor, interval, repetitions, next review date)
- SM-2 algorithm implementation:
  * Quality ratings 0-5 affect easiness factor (1.3 minimum)
  * Interval calculation: 1 day → 6 days → exponential growth
  * Forgotten cards restart from interval 0
- Routes: `/flashcards`, `/flashcards/create`, `/flashcards/deck/<id>`, `/flashcards/deck/<id>/study`, `/api/flashcards/review`
- Permission-based access control for public vs private decks
- Migration script: `migrate_flashcards.py`

### UI/UX
- Flashcards navigation link in navbar
- Deck grid with card counts, creator names, session tags
- Study/View buttons on each deck card
- Full study mode with flip animation (0.6s transition)
- Rating buttons with color-coded feedback (red/orange/green/purple)
- Progress counter during study sessions
- Completion celebration with breakdown stats
- Empty state guidance for new users

---

## [2.0.0] - 2025-11-30

### 🎉 Major Release: Real-Time Collaboration Suite

This release represents a significant overhaul of the platform with three major feature additions that transform StudyFlow into a comprehensive real-time collaboration platform.

### Added
- **🔔 Notification System**: Full in-app notification system with real-time delivery
  - Bell icon in navbar with unread count badge (animated red badge)
  - Notification dropdown panel with notification list
  - Notification types: invitation, reminder, reply, mention
  - Personal WebSocket rooms (`user_{id}`) for targeted notification delivery
  - Mark as read functionality (individual and bulk)
  - Auto-fetch unread count on page load
  - Real-time notification arrival without page refresh
  - Notifications database table with type, title, message, link, is_read
  - Backend routes: `/notifications`, `/notifications/unread-count`, `/notifications/<id>/read`, `/notifications/mark-all-read`
  - Notifications created automatically for session invitations
  - Styled notification items with type-specific icons and colors

- **🖼️ Enhanced File Preview System**: Full-screen modal preview for images and PDFs
  - `openFullPreview()` function for seamless preview experience
  - `/file/<id>/info` endpoint for file metadata retrieval
  - Modal overlay with full-screen preview
  - Iframe support for PDF viewing
  - Click-outside-to-close functionality
  - Download and delete actions in preview modal
  - Proper permission checks (creator or uploader can delete)
  - Responsive design for modal

- **📝 Collaborative Note-Taking**: Rich text editing with real-time collaboration
  - **TinyMCE Rich Text Editor Integration**
    - Full WYSIWYG editing with formatting toolbar
    - Support for: bold, italic, colors, alignment, lists, tables, links, images
    - Code view and fullscreen mode
    - Word count and character count
    - Custom content styling matching app theme
  - **Auto-Save Functionality**
    - Auto-save every 30 seconds while editing
    - `/notes/<id>/autosave` endpoint for background saves
    - Draft restoration from localStorage on create page
    - Visual feedback on auto-save completion
    - Dirty flag tracking to prevent unnecessary saves
  - **Real-Time Viewer Tracking**
    - Live "X viewing" indicator on notes
    - WebSocket-based presence system for notes
    - Note rooms (`note_{id}`) for viewer coordination
    - Viewer list with usernames shown on hover
    - Automatic viewer cleanup on disconnect
    - Join/leave room handlers for note viewing
    - Real-time viewer count updates broadcast to all participants

### Changed
- Navbar now includes notification bell icon between "Notes" and "Create Session"
- Note viewing experience enhanced with real-time collaboration features
- File preview system upgraded from simple view to full modal experience
- Create and edit note forms now use rich text editor instead of plain textarea

### Technical
- **Notifications Infrastructure**
  - Created `notifications` table: id, user_id, type, title, message, link, is_read, created_at
  - Migration script: `migrate_notifications.py`
  - `create_notification()` helper function for easy notification creation
  - WebSocket handlers: `join_user_room`, `leave_user_room`
  - Real-time emit on `new_notification` event
  - Frontend JavaScript for bell dropdown, badge updates, real-time listening

- **File Preview Enhancements**
  - New endpoint: `GET /file/<id>/info` returns JSON metadata
  - JavaScript modal system with preview content injection
  - CSS for full-screen modal with backdrop blur
  - Action buttons (close, download, delete) in modal overlay

- **Collaborative Notes**
  - TinyMCE 6 CDN integration
  - WebSocket note viewers tracking with in-memory store
  - Note room system for real-time presence
  - Auto-save endpoint with JSON request/response
  - Disconnect handler cleanup for note viewers
  - CSS styling for viewer indicator with gradient background
  - localStorage draft system for unsaved work recovery

### Dependencies
- TinyMCE 6.x (CDN)
- Socket.IO 4.5.4 (already in use, extended for notes and notifications)

---

## [1.10.0] - 2025-11-30

### Added
- **Study Analytics Dashboard**: Comprehensive dashboard with Chart.js visualizations
- Total study hours tracking across all attended sessions
- Session attendance counter and favorite subject identification
- Study streak calculator showing consecutive days of study
- **Four Interactive Charts**:
  - Line chart: Study sessions over time (last 30 days)
  - Doughnut chart: Study by subject breakdown
  - Bar chart: Study hours by day of week
  - Dual-axis bar chart: Monthly progress (sessions + hours, last 6 months)
- Summary statistics cards with gradient icons
- Recent activity feed showing last 5 attended sessions
- Responsive grid layout optimized for desktop and mobile

### Technical
- New `/analytics` route with comprehensive data aggregation
- Chart.js 4.4.0 integration via CDN
- Analytics calculations from `sessions`, `rsvps`, and `users` tables
- Day-of-week analysis (Monday-Sunday pattern)
- Monthly aggregation with dual metrics
- SQL queries optimized for large datasets
- Streak calculation using consecutive date logic

### UI/UX
- 4 gradient stat cards with Font Awesome icons
- Card hover effects (lift and shadow)
- Chart containers with white background and shadows
- Activity items with session type icons
- Responsive grid adapting from 4-column to 1-column on mobile
- Purple gradient theme consistency maintained

### Dependencies
- Chart.js 4.4.0 (CDN)
- Inter font family
- Font Awesome 6.5.1 (already in use)

---

## [1.11.0] - 2025-11-30

### Added
- **Calendar Integration**: Export study sessions to calendar applications
- .ics file generation for universal calendar compatibility
- **Google Calendar Integration**: Direct "Add to Google Calendar" button with deep linking
- **Outlook Calendar Integration**: Direct "Add to Outlook Calendar" button with deep linking
- Calendar dropdown menu with multiple export options
- "Add to Calendar" buttons on session detail pages (for participants only)
- Calendar export buttons on session cards in index page
- Session metadata included in calendar events:
  - Title, date, time, duration (default 2 hours)
  - Subject, type, location (if in-person)
  - Meeting link (if remote)
  - Organizer name

### Technical
- New `/session/<id>/calendar.ics` route for .ics file download
- `ics` library (0.7.2) for iCalendar format generation
- JavaScript functions for Google/Outlook deep link generation
- ISO 8601 datetime formatting for calendar APIs
- Permission checks: Only participants and creators can export sessions
- Calendar dropdown with click-outside-to-close functionality

### UI/UX
- Calendar buttons with gradient purple styling
- Dropdown menu with Google/Outlook/Download options
- Responsive calendar buttons (full-width on mobile)
- Calendar option icons (Google, Microsoft, Download)
- Hover effects and smooth transitions
- Small calendar buttons on session cards in index

### Dependencies
- ics==0.7.2 (Python library for iCalendar generation)

---

## [1.12.0] - 2025-11-30

### Added
- **Mobile-Responsive Design**: Complete mobile optimization for all devices
- **Hamburger Menu**: Animated 3-bar menu for mobile navigation
- Slide-in mobile menu with smooth transitions
- Touch-friendly navigation with full-width links
- Mobile-optimized layouts for all pages and components
- Responsive typography scaling (14-16px on mobile)
- Single-column grid layouts on mobile (<768px)
- Optimized form inputs (16px font to prevent iOS zoom)
- Mobile-friendly modals and dropdowns
- Landscape orientation optimizations
- Print-friendly styles

### Technical
- CSS media queries for tablets (1024px), phones (768px), small phones (480px)
- Hamburger menu JavaScript with click-outside-to-close
- Flexbox-based mobile navigation layout
- Fixed positioning for mobile menu overlay
- Viewport-aware font sizing
- Touch target optimization (44px minimum)
- Menu state management with body class toggling
- Auto-close menu on link click

### UI/UX Improvements
- **Navbar**: Hamburger menu button, slide-in drawer navigation
- **Session Cards**: Single column layout, full-width buttons
- **Forms**: Stacked inputs, larger touch targets
- **Charts**: Reduced height for mobile (220-250px)
- **Modals**: 95% width, 90vh max height on mobile
- **Tables**: Responsive participant lists, single column
- **Buttons**: Full-width on mobile where appropriate
- **Typography**: Scaled down headings (h1: 1.75rem on mobile)
- **Spacing**: Reduced padding/margins for smaller screens
- **File Grid**: Single column file cards
- **Analytics**: Mobile-optimized stat cards and charts
- **Chat**: Reduced message container height (400px)
- **Recordings**: Stacked recording actions on mobile
- **TinyMCE**: Minimum 300px height on mobile

### Accessibility
- Proper ARIA labels on hamburger button
- Semantic HTML for mobile menu
- Keyboard navigation support
- Focus management for menu interactions
- Print styles for document export

### Performance
- CSS-only animations (no JavaScript lag)
- Optimized media query breakpoints
- Minimal JavaScript for menu toggle
- No additional HTTP requests

---

## [1.9.0] - 2025-11-30

### Added
- **Session Recording and Transcription**: Upload, manage, and transcribe audio/video recordings
- Support for 8 audio/video formats (mp3, wav, ogg, m4a, webm, mp4, avi, mov)
- Manual transcription with inline editing forms
- Recording list with file details (uploader, date, duration, file size)
- Download recordings (participants only)
- Delete recordings (uploader or session creator only)
- Recording type detection (audio vs video)
- Visual icons for audio and video files

### Technical
- New `session_recordings` table with foreign keys to sessions and users
- Four recording management routes:
  - POST `/session/<id>/upload-recording`: Upload audio/video files
  - GET `/recording/<id>/download`: Download recordings (participants only)
  - POST `/recording/<id>/delete`: Delete recordings (uploader/creator only)
  - POST `/recording/<id>/transcription`: Add/update transcriptions
- File validation and secure filename handling
- Permission-based access control for downloads and deletions
- Migration script (`migrate_recordings.py`) for database updates

### UI/UX
- Recordings section in session detail page
- Upload form with file input and optional transcription field
- Recording cards with gradient backgrounds
- Inline transcription editing with show/cancel/save actions
- JavaScript functions for transcription management
- Responsive design for mobile devices

---

## [1.7.0] - 2025-11-30

### Added
- **User Presence Indicators**: Real-time online/offline status for session participants
- Green dot indicator for online users with pulsing animation
- Gray dot for offline users
- Automatic presence tracking when users join/leave sessions
- Real-time presence updates via WebSocket

### Changed
- Enhanced join/leave WebSocket handlers to broadcast user presence
- Updated participant list to show presence indicators
- Improved visual feedback for active vs inactive participants

### Technical
- New WebSocket events: `user_joined` and `user_left` with user_id/user_name
- Enhanced `join_session` and `leave_session` handlers to include user data
- CSS animations for online presence indicator (pulsing green dot)
- Automatic presence cleanup on page unload

---

## [1.6.0] - 2025-11-30

### Added
- **File Sharing in Chat**: Upload files directly in chat messages (separate from study materials)
- File preview thumbnails for images inline with messages
- File type icons for PDFs, Word, Excel, PowerPoint documents
- Quick file actions (View and Download) on each file message
- Real-time file broadcast via WebSocket (`chat_file` event)
- Merged timeline showing both messages and files chronologically

### Changed
- Messages and chat files now display in unified timeline
- Updated file upload to support dual context (chat vs study materials)
- Enhanced message display logic to differentiate between text and file messages
- File messages show with distinctive styling and preview capabilities

### Technical
- Added `type` field to message objects ('message' or 'file')
- New WebSocket event: `chat_file` for broadcasting chat file uploads
- Updated `createMessageElement()` to handle both message types
- Enhanced file message rendering with preview thumbnails
- CSS styles for file messages with image previews and file type icons

---

## [1.5.0] - 2025-11-30

### Added
- **Typing Indicators**: Real-time "user is typing..." display in chat
- Animated typing dots with smooth transitions
- Multi-user typing support (shows "3 people are typing")
- Smart typing detection (stops after 1 second of inactivity)
- Automatic typing stop when message is sent

### Changed
- Enhanced WebSocket communication with typing events
- Improved chat UX with real-time presence feedback

### Technical
- New WebSocket handler: `@socketio.on('typing')` for broadcasting typing status
- New WebSocket event: `user_typing` for receiving typing updates
- JavaScript typing detection with debounce logic
- CSS animations for typing indicator dots
- Excludes sender from receiving their own typing events

---

## [1.4.0] - 2025-11-30

### Added
- **Message Reactions**: React to messages with emoji (👍 ❤️ 😂 🎉 😕 🔥 👏 ✅)
- **Message Threading**: Reply to specific messages to create threaded conversations
- Reaction picker UI with common emojis
- Reply context indicator showing parent message
- Real-time reaction updates via WebSocket
- `message_reactions` database table with unique constraint
- `parent_message_id` column in messages table for threading
- Action buttons (reply and react) shown on message hover
- Visual feedback for user's own reactions (purple gradient highlight)
- Cancel reply functionality
- Migration script (`migrate_reactions.py`) for existing databases

### Changed
- Updated message display to include reactions and reply references
- Enhanced `post_message` route to support parent_message_id
- Updated `get_messages` API to include reactions and parent info
- Improved message UI with hover actions
- Message data structure now includes reactions array and parent_info

### Technical
- New route: `POST /message/<message_id>/react` for adding/removing reactions
- New WebSocket event: `reaction_updated` for broadcasting reaction changes
- Enhanced `new_message` WebSocket event with parent info and reactions
- CSS styles for reaction badges, reply references, and action buttons
- JavaScript functions: `toggleReaction()`, `showReplyForm()`, `cancelReply()`

---

## [1.3.0] - 2025-11-30

### Added
- WebSocket-based real-time communication using Flask-SocketIO
- Instant message delivery without polling
- Real-time file upload notifications
- Session room system for isolated real-time updates
- Socket.IO client library integration

### Changed
- Replaced 3-second polling with WebSocket events for messages
- Replaced 5-second polling with WebSocket events for files  
- Improved server performance by eliminating constant polling requests
- Messages and files now appear instantly for all session participants

### Removed
- AJAX polling intervals for messages and files
- `pollMessages()` and `pollFiles()` functions
- Polling-related code and intervals

### Performance
- Reduced server load by ~60-80% (no more constant polling requests)
- Improved battery life on mobile devices
- Instant updates instead of 3-5 second delays

---

## [1.2.0] - 2025-11-30

### Added
- Full-screen file preview modal with darkened overlay
- Preview action buttons (Close, Download, Delete)
- Permission-based delete button (only owner/creator can delete)
- Fit-to-screen image display with smooth animations
- Comprehensive documentation suite:
  - QUICKSTART.md - Quick start guide
  - DEVELOPMENT.md - Development roadmap with 15+ feature ideas
  - DEPLOYMENT.md - Production deployment guide (PythonAnywhere, Heroku, AWS, DigitalOcean)
  - API.md - Internal API documentation
  - CONTRIBUTING.md - Contribution guidelines
  - TROUBLESHOOTING.md - Common issues and solutions
  - LICENSE - MIT License
  - Enhanced README.md with badges and complete overview

### Changed
- Preview modal now uses full-screen darkened overlay (95% opacity)
- Images now display with object-fit: contain for better viewing
- Action buttons positioned top-right with smooth slide-in animation
- Preview animations updated from slideInUp to zoomIn effect

### Fixed
- Preview modal display issues
- Image sizing problems in preview
- Button positioning in preview overlay

---

## [1.1.0] - 2025-11-29

### Added
- Horizontal card layout for study materials (4 cards per row)
- "See Older Materials" toggle button for files beyond 4
- Image thumbnails with hover effects
- File preview support for images (PNG, JPG, JPEG, GIF)
- PDF preview in modal window
- Quick file upload from chat interface
- Separate file contexts: 'chat' vs 'study_material'
- `file_context` column in database

### Changed
- File cards now display in responsive grid layout
- Study materials and chat files tracked separately
- File upload forms accept context parameter
- Preview opens in modal instead of new tab

### Fixed
- File upload only showing in one location
- File organization issues
- Chat file handling

---

## [1.0.0] - 2025-11-28

### Added
- Complete UI redesign with purple gradient theme
- Glass morphism effects throughout application
- Inter font from Google Fonts
- Smooth animations and transitions
- Hover effects on interactive elements
- Responsive design for mobile devices

### Changed
- Primary color scheme to purple gradient (#667eea → #764ba2 → #f093fb)
- All buttons to gradient style with glass effect
- Cards to frosted glass appearance
- Navigation bar with gradient background

### Fixed
- Text contrast issues on navbar and buttons
- Message bubble spacing (green border too close to text)
- Overall visual consistency

---

## [0.9.0] - 2025-11-27

### Added
- Real-time chat with automatic refresh (3-second polling)
- Real-time file updates (5-second polling)
- Duplicate message prevention
- Duplicate file prevention
- AJAX endpoints for messages and files
- Client-side polling with last ID tracking

### Changed
- Chat interface to support real-time updates
- File display to auto-refresh
- Message sending to return immediately

### Fixed
- Messages requiring page refresh to appear
- Files not showing for other users until refresh
- Chat synchronization issues

---

## [0.8.0] - 2025-11-26

### Added
- File upload functionality for study materials
- Support for images, PDFs, Office documents, archives
- File size limit (100MB)
- File type validation
- Secure filename handling
- File download route
- File deletion (owner/creator only)

### Changed
- Session detail page to include file management section
- Database schema to include files table

### Security
- Added file extension validation
- Implemented secure filename sanitization
- Added permission checks for file operations

---

## [0.7.0] - 2025-11-25

### Added
- Personal notes system for sessions
- Notes creation and editing
- Auto-save for notes
- Last updated timestamp
- Notes database table

### Changed
- Session detail page to include notes section

---

## [0.6.0] - 2025-11-24

### Added
- Automatic email reminders 24 hours before sessions
- APScheduler for background task scheduling
- Email configuration setup
- Reminder scheduling on session creation
- SMTP integration

### Changed
- Session creation to schedule reminders
- App initialization to start scheduler

---

## [0.5.0] - 2025-11-23

### Added
- Real-time chat functionality
- Message sending and display
- Chat history
- Message timestamps
- Username display for messages

### Changed
- Session detail page to include chat interface
- Database schema to include messages table

---

## [0.4.0] - 2025-11-22

### Added
- Invitation system
- Send invitations to users
- Accept/decline invitations
- View pending invitations
- Invitation notifications

### Changed
- Dashboard to show invitations
- Session detail to manage invitations

---

## [0.3.0] - 2025-11-21

### Added
- Session RSVP functionality
- Accept/decline session participation
- Attendee management
- Max attendees enforcement
- RSVP status tracking

### Changed
- Sessions table to track RSVPs
- Session detail page to show RSVP status

---

## [0.2.0] - 2025-11-20

### Added
- Study session creation
- Session editing (creator only)
- Session deletion (creator only)
- Session details page
- Dashboard with user's sessions
- Countdown timer to sessions

### Changed
- Database schema to include sessions table
- Homepage to show public sessions

---

## [0.1.0] - 2025-11-19

### Added
- User authentication system
- User registration (signup)
- User login
- User logout
- Password hashing with Werkzeug
- Session management
- Protected routes

### Changed
- Initial Flask app setup
- SQLite database configuration
- Basic templates and styling

---

## [0.0.1] - 2025-11-18

### Added
- Initial project setup
- Flask installation
- Basic project structure
- Hello World endpoint
- Git repository initialization

---

## Version Number Guide

Given a version number MAJOR.MINOR.PATCH:
- **MAJOR**: Incompatible API changes
- **MINOR**: New features (backwards-compatible)
- **PATCH**: Bug fixes (backwards-compatible)

## Links

- [Repository](https://github.com/YOUR_USERNAME/HackDecouverteStudyApp)
- [Issues](https://github.com/YOUR_USERNAME/HackDecouverteStudyApp/issues)
- [Pull Requests](https://github.com/YOUR_USERNAME/HackDecouverteStudyApp/pulls)

---

**Last Updated**: November 30, 2025
