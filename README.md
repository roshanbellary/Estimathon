# Estimathon Webapp

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set up a MongoDB database (local or Atlas).
3. Create a `.env` file with your MongoDB URI:
   ```env
   MONGO_URI=mongodb://localhost:27017/estimathon
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=your_admin_password
   ```
4. Run the app:
   ```bash
   streamlit run app.py
   ```

## Features
- User signup/login
- Team creation and joining
- Admin controls to start contest
- 20-question answering interface with scoring
