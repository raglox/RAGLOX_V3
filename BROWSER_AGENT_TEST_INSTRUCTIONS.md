# RAGLOX v3.0 - Browser Agent Visual UI Testing Instructions

## Mission Overview
You are a visual testing agent tasked with reviewing and evaluating the RAGLOX v3.0 Security Operations Platform UI. Your goal is to ensure the interface meets **enterprise-grade SaaS standards** comparable to platforms like Datadog, Splunk, CrowdStrike, or Palo Alto Networks.

## Access URLs
| Service | URL |
|---------|-----|
| **Frontend** | http://172.245.232.188:3000 |
| **Backend API** | http://172.245.232.188:8000 |
| **API Documentation** | http://172.245.232.188:8000/docs |

## Test Data Available
- **Mission ID**: `6b14028c-7f30-4ce6-aad2-20f17eee39d0`
- **Target IP**: 172.28.0.100 (Linux Ubuntu 22.04)
- **Risk Score**: 85.0 (High)
- **Open Ports**: SSH (22), HTTP (80), PostgreSQL (5432)
- **Vulnerabilities**: 2 (SSH Weak Password - High, DB Credentials in File - Critical)
- **Credentials**: 2 (postgres/database, admin/SSH)
- **Active Sessions**: 1 (SSH as root)

---

## TESTING CHECKLIST

### Phase 1: Overall Visual Assessment (Homepage `/`)

#### 1.1 Layout & Structure
- [ ] **Header/Navigation**: Is there a clear header with branding (RAGLOX logo)?
- [ ] **Sidebar Navigation**: Is the sidebar visible and properly styled?
- [ ] **Content Area**: Is the main content area properly sized and positioned?
- [ ] **Responsive Design**: Does the layout feel balanced and professional?

#### 1.2 Color Scheme & Typography
- [ ] **Dark Theme Consistency**: Is the dark theme applied consistently across all elements?
- [ ] **Color Hierarchy**: Are accent colors (blue, green, red, yellow) used meaningfully?
- [ ] **Font Readability**: Are fonts legible? Is there proper contrast?
- [ ] **Font Consistency**: Is the same font family used throughout (Inter, JetBrains Mono)?

#### 1.3 Visual Polish
- [ ] **Shadows & Depth**: Are there subtle shadows/borders creating depth?
- [ ] **Border Radius**: Are corners consistently rounded (8px, 12px, 16px)?
- [ ] **Spacing**: Is padding/margin consistent (8px grid system)?
- [ ] **Icons**: Are Lucide icons properly sized and aligned?

#### 1.4 Loading & Status
- [ ] **WebSocket Indicator**: Is there a connection status indicator?
- [ ] **Loading States**: Are there skeleton loaders or spinners?

---

### Phase 2: Workspace A - Recon View (`/recon`)

Navigate to: **http://172.245.232.188:3000/recon**

#### 2.1 Stats Bar
- [ ] **Stats Cards**: Are there stat cards showing Targets, Open Ports, Vulns, Owned, OS Types?
- [ ] **Numbers Visible**: Do the numbers display correctly (not 0 if data exists)?
- [ ] **Card Styling**: Do cards have proper backgrounds, borders, and icons?

#### 2.2 Toolbar
- [ ] **Search Input**: Is there a search field with placeholder text?
- [ ] **Group By Dropdown**: Is there a dropdown to group by OS/Priority/Status/Subnet?
- [ ] **View Toggle**: Are there Grid/List view toggle buttons?
- [ ] **Target Count Badge**: Does it show the correct count (e.g., "1 targets")?

#### 2.3 Asset Cards (Critical Component)
- [ ] **Card Visibility**: Is there at least one Asset Card visible for 172.28.0.100?
- [ ] **OS Icon**: Is there a Linux icon (penguin or server icon)?
- [ ] **IP Address**: Is "172.28.0.100" clearly displayed?
- [ ] **Hostname**: Is "vuln-target-001" shown?
- [ ] **Risk Score Badge**: Is "85.0" displayed with red/high-risk coloring?
- [ ] **Port Badges**: Are ports (22, 80, 5432) shown as small badges?
- [ ] **Status Indicator**: Is there a "scanned" or similar status badge?
- [ ] **Priority Indicator**: Is "high" priority indicated?

#### 2.4 Deep Dive Drawer
- [ ] **Click Interaction**: Does clicking an Asset Card open a drawer/panel?
- [ ] **Target Details**: Does the drawer show detailed target information?
- [ ] **Port Details**: Are ports listed with their services (ssh, http, postgresql)?
- [ ] **Close Button**: Is there a way to close the drawer?

---

### Phase 3: Workspace B - Operations View (`/operations`)

Navigate to: **http://172.245.232.188:3000/operations**

#### 3.1 Mission Timeline
- [ ] **Timeline Visible**: Is there a mission timeline component?
- [ ] **Phase Indicators**: Are there phase markers (Recon, Vuln Scan, Exploitation, Post-Exploitation)?
- [ ] **Event Cards**: Are timeline events displayed as cards?
- [ ] **Timestamps**: Do events have timestamps?
- [ ] **Status Colors**: Are completed events green, pending yellow, failed red?

#### 3.2 Quick Stats
- [ ] **Phase Display**: Is the current phase shown?
- [ ] **Completed Count**: Number of completed events?
- [ ] **Pending Count**: Number of pending events?
- [ ] **Goals Progress**: Goals achieved vs total?

#### 3.3 HITL Decision Room (if visible)
- [ ] **Pending Approvals**: Is there a section for pending approvals?
- [ ] **Approval Cards**: Do approval requests show action type, risk level?
- [ ] **Approve/Reject Buttons**: Are action buttons present and styled?
- [ ] **Risk Modal**: Does clicking an approval open a detailed risk modal?

#### 3.4 Status Indicators
- [ ] **Mission Status Badge**: Is current status (running/paused/stopped) shown?
- [ ] **System Health**: Is there a health indicator?

---

### Phase 4: Workspace C - Loot View (`/loot`)

Navigate to: **http://172.245.232.188:3000/loot**

#### 4.1 Stats Summary Bar
- [ ] **Sessions Count**: Shows "1" active session?
- [ ] **Credentials Count**: Shows "2" credentials?
- [ ] **Privileged Count**: Shows count of admin/root credentials?
- [ ] **Verified Count**: Shows count of verified credentials?
- [ ] **Artifacts Count**: Shows "0" (no artifacts yet)?

#### 4.2 Tab Navigation
- [ ] **Sessions Tab**: Is there a Sessions tab with badge?
- [ ] **Credentials Tab**: Is there a Credentials tab with badge?
- [ ] **Artifacts Tab**: Is there an Artifacts tab?
- [ ] **Active Tab Styling**: Is the active tab visually distinct?

#### 4.3 Sessions Tab (Session Manager)
- [ ] **Session Table/Cards**: Are sessions displayed in a table or cards?
- [ ] **Session Info**: Is session type (SSH), user (admin), privilege (root) shown?
- [ ] **Status Badge**: Is "active" status shown in green?
- [ ] **Target Reference**: Is the target (172.28.0.100) referenced?
- [ ] **Open Terminal Button**: Is there a button to open terminal?
- [ ] **Kill Session Button**: Is there an option to terminate session?

#### 4.4 Credentials Tab (Credential Vault)
- [ ] **Credentials Table**: Are credentials displayed in a table format?
- [ ] **Username Column**: Are usernames (postgres, admin) visible?
- [ ] **Password Masking**: Are passwords masked with dots (••••••)?
- [ ] **Reveal Button**: Is there a button to reveal passwords?
- [ ] **Type Column**: Is credential type (database, SSH) shown?
- [ ] **Privilege Level**: Is privilege (admin, root) indicated?
- [ ] **Source Column**: Is credential source shown (~/.db_creds, bruteforce)?
- [ ] **Verified Badge**: Are verified credentials marked with a checkmark?
- [ ] **Test Credential Button**: Is there an option to test credentials?

#### 4.5 Artifacts Tab
- [ ] **Empty State**: Is there a proper empty state message?
- [ ] **Icon & Text**: Does empty state have an icon and helpful text?

---

### Phase 5: Intelligence Sidebar (if visible)

#### 5.1 AI Co-pilot Panel
- [ ] **Toggle Button**: Is there a toggle to show/hide the AI panel?
- [ ] **Panel Visibility**: When opened, does it slide in from the right?
- [ ] **Recommendations**: Are there AI recommendations or insights?
- [ ] **Chat Interface**: Is there a chat-like interface?

---

### Phase 6: Emergency Stop & Control

#### 6.1 Emergency Stop Button
- [ ] **Button Visibility**: Is there a prominent red Emergency Stop button?
- [ ] **Button Position**: Is it easily accessible (fixed position)?
- [ ] **Button Styling**: Does it look urgent/dangerous (red, bold)?
- [ ] **Click Behavior**: Does clicking open a confirmation dialog?
- [ ] **ABORT Confirmation**: Does the dialog require typing "ABORT"?
- [ ] **Cancel Option**: Can the user cancel the emergency stop?

---

### Phase 7: Navigation & Sidebar

#### 7.1 Sidebar Items
- [ ] **Overview Link**: Link to `/` - Dashboard
- [ ] **Recon Link**: Link to `/recon` with Target icon
- [ ] **Operations Link**: Link to `/operations` with Activity icon
- [ ] **Loot Link**: Link to `/loot` with Key icon
- [ ] **New Mission Link**: Link to `/mission/new`
- [ ] **Settings Link**: Link to `/settings`

#### 7.2 Sidebar Behavior
- [ ] **Active State**: Is the current page highlighted in sidebar?
- [ ] **Hover Effects**: Do items have hover states?
- [ ] **Badges**: Do links show dynamic badges (session count, pending approvals)?
- [ ] **Collapse/Expand**: Can the sidebar be collapsed?

---

### Phase 8: Mission Setup Wizard (`/mission/new`)

Navigate to: **http://172.245.232.188:3000/mission/new**

#### 8.1 Wizard Structure
- [ ] **Step Indicator**: Is there a step progress indicator?
- [ ] **Step 1 - Define Scope**: Is there a form to enter targets?
- [ ] **Step 2 - Select Intensity**: Is there an intensity selector?
- [ ] **Step 3 - Launch**: Is there a launch/confirm step?

#### 8.2 Form Elements
- [ ] **Input Fields**: Are text inputs properly styled?
- [ ] **Buttons**: Are Next/Back/Launch buttons present?
- [ ] **Validation**: Are there error states for invalid input?

---

## QUALITY CRITERIA (Enterprise Standards)

### Visual Consistency Score (Rate 1-10)
| Criteria | Expected |
|----------|----------|
| **Color Consistency** | Same accent colors used for same meaning throughout |
| **Typography Hierarchy** | Clear distinction between headings, body, captions |
| **Component Consistency** | Same style for similar components (all cards look alike) |
| **Icon Consistency** | Same icon family, consistent sizing |
| **Animation/Transitions** | Smooth, subtle animations (not jarring) |

### Usability Score (Rate 1-10)
| Criteria | Expected |
|----------|----------|
| **Information Hierarchy** | Most important info is prominent |
| **Scannability** | Can quickly scan and find information |
| **Actionability** | Clear calls to action, obvious buttons |
| **Feedback** | Hover states, loading states, success/error states |
| **Error Prevention** | Confirmation dialogs for dangerous actions |

### Enterprise Readiness Score (Rate 1-10)
| Criteria | Expected |
|----------|----------|
| **Professional Appearance** | Looks like Datadog/Splunk/CrowdStrike |
| **Data Density** | Shows useful data without clutter |
| **Real-time Updates** | Data updates without page refresh |
| **Accessibility** | Proper contrast, keyboard navigation |
| **Branding** | Clear product identity |

---

## ISSUES TO REPORT

For each issue found, report:
1. **Location**: Page URL and component name
2. **Severity**: Critical / High / Medium / Low
3. **Description**: What's wrong
4. **Expected**: What should it look like
5. **Screenshot**: If possible, capture the issue
6. **Recommendation**: How to fix it

### Issue Categories
- **Visual Bug**: Styling issue, misalignment, wrong color
- **Functional Bug**: Feature not working as expected
- **UX Issue**: Confusing interaction, missing feedback
- **Content Issue**: Missing text, wrong label, typo
- **Performance Issue**: Slow loading, janky animation

---

## FINAL DELIVERABLES

After completing all tests, provide:

1. **Overall Score** (1-100) with breakdown:
   - Visual Design: /30
   - Usability: /30  
   - Functionality: /25
   - Enterprise Readiness: /15

2. **Top 5 Strengths**: What the UI does well

3. **Top 5 Critical Issues**: Must-fix before production

4. **Recommendations**: Specific improvements for enterprise-grade appearance

5. **Comparison**: How does this compare to industry standards (Datadog, Splunk, etc.)?

---

## NOTES FOR AGENT

- Take your time to explore each page thoroughly
- Scroll down to see all content
- Interact with elements (click, hover)
- Check responsive behavior if possible
- Focus on details that enterprise customers would notice
- The goal is a **world-class security operations UI**

**Current Mission ID for testing**: `6b14028c-7f30-4ce6-aad2-20f17eee39d0`
