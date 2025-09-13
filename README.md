# Anonyma - Anonymous Chat Platform

[![Anonymous Chat](https://img.shields.io/badge/Anonymous-Chat-blue?style=for-the-badge&logo=chat)](https://github.com/your-username/anonyma-chat)
[![Flask 2.3.3](https://img.shields.io/badge/Flask-2.3.3-green?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Socket.IO 5.3.6](https://img.shields.io/badge/Socket.IO-5.3.6-orange?style=for-the-badge&logo=socket.io)](https://socket.io/)
[![AI Assistant](https://img.shields.io/badge/AI-Assistant-purple?style=for-the-badge&logo=ai)](https://openrouter.ai/)

**Anonyma** is a privacy-focused chat platform designed for developers and teams to collaborate in real-time without the need for accounts or sign-ups. Share code, discuss ideas, and get instant AI-powered assistance - all while maintaining complete anonymity.

---

## 🚀 Features

- 🔒 **Complete Anonymity:** No accounts or personal information required  
- 💬 **Real-time Chat:** Instant messaging with Socket.IO technology  
- 💻 **Code Sharing:** Beautiful code blocks with syntax highlighting and copy functionality  
- 🤖 **AI Assistant:** Get instant code explanations with integrated AI technology  
- 🔐 **Private Rooms:** Optional password protection for sensitive discussions  
- 📱 **Responsive Design:** Works perfectly on desktop and mobile devices  
- ⚡ **Instant Access:** Join chats immediately without registration  
- 🧹 **Auto Cleanup:** Rooms automatically expire after 24 hours of inactivity  

---

## 🛠️ Technology Stack

- **Backend:** Flask (Python)  
- **Real-time Communication:** Flask-SocketIO  
- **AI Processing:** OpenRouter API with LLaMA 3.3 70B model  
- **Frontend:** HTML5, CSS3, JavaScript  
- **Security:** Werkzeug password hashing  
- **Deployment:** Ready for production with ProxyFix support  

---

## 📦 Installation

### Clone the Repository
```bash
git clone https://github.com/Yuvakunaal/Anonyma.git
cd anonyma-chat
```
### Install Dependencies
```bash
pip install -r requirements.txt
```
### Environment Configuration
Create a .env file with the following variables:
```env
SECRET_KEY=your-secret-key-here
OPENROUTER_API_KEY=your-openrouter-api-key
ADMIN_PASSWORD=your-admin-password
ADMIN_SECRET_KEY=your-admin-secret-key
ROOM_TIMEOUT_HOURS=24
CLEANUP_INTERVAL_SECONDS=3600
MAX_ROOMS_PER_IP=5
```
### 🔑 How to Get OpenRouter API Key

1. Go to [https://openrouter.ai/](https://openrouter.ai/).
2. Log in with your account.
3. Go to **Settings**.
4. Navigate to **Keys**.
5. Click on **Create Key**, give it a name.
6. Copy the generated key.
7. Paste it as the value of the `OPENROUTER_API_KEY` variable in your project (.env).


### Run the Application
```bash
python3 app.py
```
**Open Browser: Navigate to http://localhost:8070/**

# 🎯 How It Works

## For Users:
- **Create or Join a Room**: From the home page, create a new room or join an existing one.
- **Set Display Name**: Choose any temporary name (not stored after you leave).
- **Start Collaborating**: Chat, share code, and use AI assistant features.
- **Share Room URL**: Invite others by sharing your room's unique URL.

## For Developers:
- **Code Sharing**: Use the code editor (Ctrl+K toggle) or paste code directly.
- **AI Assistance**: Click the "AI ✨" button on any code block for instant explanations.
- **Real-time Collaboration**: See others type and collaborate seamlessly.

# 🔧 API Endpoints (Imp)
- `/` – Home
- `/admin` - Admin only

# 🛡️ Security Features
- **Password Hashing**: All room passwords are securely hashed.
- **IP Rate Limiting**: Maximum 5 rooms per IP per day.
- **Session Management**: Secure session-based room access.
- **Auto Cleanup**: Inactive rooms are automatically deleted.
- **No Permanent Storage**: All data is temporary and ephemeral.

# 👨‍💻 Admin Features
Access the admin dashboard at `/admin` with the following capabilities:
- View all active rooms and statistics.
- Create rooms with admin override privileges.
- Delete rooms and manage users.
- Monitor system-wide metrics.

# 🚨 Limitations

- **Room Expiry**: All rooms automatically expire after 24 hours of inactivity.
- **Room Creation**: Maximum 5 rooms per day per user.
- **Message History**: Only the last 100 messages are preserved in active rooms.
- **AI Rate Limits**: Subject to third-party API limitations during high traffic.

# 👨‍💻 Developer

Kunaal – Full Stack Developer & AI Enthusiast

# 🙏 Acknowledgments

- OpenRouter for providing AI API access.
- Flask and Socket.IO communities for excellent documentation.

> ⭐ If you find this project useful, please consider giving it a star on GitHub!
