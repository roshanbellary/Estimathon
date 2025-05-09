import os
import streamlit as st
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import re
import random
import string
import json
from streamlit_cookies_controller import CookieController

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

client = MongoClient(MONGO_URI)
db = client.get_database()
users_col = db["users"]
teams_col = db["teams"]
contest_col = db["contest_state"]
questions_col = db["questions"]
team_answers_col = db["team_answers"]

MAX_ATTEMPTS = 40

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def user_exists(email):
    return users_col.find_one({"email": email}) is not None

def create_user(email, password, is_admin=False):
    hashed = hash_password(password)
    users_col.insert_one({
        "email": email,
        "password": hashed,
        "is_admin": is_admin,
        "team_id": None
    })

def ensure_admin():
    if not user_exists(ADMIN_EMAIL):
        create_user(ADMIN_EMAIL, ADMIN_PASSWORD, is_admin=True)

def valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def valid_password(password):
    return len(password) >= 6

def authenticate(email, password):
    user = users_col.find_one({"email": email})
    if user and check_password(password, user["password"]):
        return user
    return None

def login_form(controller=None):
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    login_btn = st.button("Login")
    if login_btn:
        if not valid_email(email):
            st.error("Please enter a valid email address.")
            return
        user = authenticate(email, password)
        if user:
            st.session_state["user"] = user
            if controller:
                controller.set('estimathon_user', user["email"])
            st.success("Logged in!")
            st.rerun()
        else:
            st.error("Invalid credentials.")
    if st.button("Go to Signup"):
        st.session_state["auth_mode"] = "signup"
        st.rerun()

def signup_form():
    st.subheader("Sign Up")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    signup_btn = st.button("Sign Up")
    if signup_btn:
        if not valid_email(email):
            st.error("Please enter a valid email address.")
            return
        if not valid_password(password):
            st.error("Password must be at least 6 characters.")
            return
        if user_exists(email):
            st.error("User already exists.")
            return
        create_user(email, password, is_admin=(email == ADMIN_EMAIL))
        st.success("Account created! Please log in.")
        st.session_state["auth_mode"] = "login"
        st.rerun()
    if st.button("Go to Login"):
        st.session_state["auth_mode"] = "login"
        st.rerun()


def generate_join_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_team(team_name, creator_email):
    join_code = generate_join_code()
    team = {
        "name": team_name,
        "join_code": join_code,
        "members": [creator_email]
    }
    result = teams_col.insert_one(team)
    users_col.update_one({"email": creator_email}, {"$set": {"team_id": result.inserted_id}})
    return join_code

def join_team(join_code, user_email):
    team = teams_col.find_one({"join_code": join_code})
    if not team:
        return False, "No team with that join code."
    if user_email in team["members"]:
        return False, "You are already in this team."
    if len(team["members"]) >= 5:
        return False, "This team already has the maximum number of members (5)."
    teams_col.update_one({"_id": team["_id"]}, {"$push": {"members": user_email}})
    users_col.update_one({"email": user_email}, {"$set": {"team_id": team["_id"]}})
    return True, team["name"]

def get_team(user):
    if not user.get("team_id"):
        return None
    return teams_col.find_one({"_id": user["team_id"]})

def leave_team(user):
    user = users_col.find_one({"email": user["email"]})
    if not user.get("team_id"):
        return
    team_id = user["team_id"]
    teams_col.update_one({"_id": team_id}, {"$pull": {"members": user["email"]}})
    users_col.update_one({"email": user["email"]}, {"$set": {"team_id": None}})
    team = teams_col.find_one({"_id": team_id})
    if team and (not team.get("members") or len(team["members"]) == 0):
        teams_col.delete_one({"_id": team_id})

def team_management(user):
    if user.get("is_admin"):
        return;
    user = users_col.find_one({"email": user["email"]})  # Refresh
    if user.get("team_id"):
        team = get_team(user)
        st.success(f"You are in team: {team['name']}")
        st.info(f"Join code: {team['join_code']}")
        st.write("Team members:")
        for member in team["members"]:
            st.write(f"- {member}")
        if get_contest_state() == "not_started" and st.button("Leave Team"):
            leave_team(user)
            st.success("You have left the team.")
            st.rerun()
        return
    st.subheader("Create or Join a Team")
    create_col, join_col = st.columns(2)
    with create_col:
        st.write("Create a new team:")
        team_name = st.text_input("Team Name")
        if st.button("Create Team"):
            if not team_name:
                st.error("Please enter a team name.")
            else:
                join_code = create_team(team_name, user["email"])
                st.success(f"Team '{team_name}' created! Join code: {join_code}")
                st.rerun()
    with join_col:
        st.write("Join an existing team:")
        join_code = st.text_input("Join Code (from your teammate)")
        if st.button("Join Team"):
            ok, msg = join_team(join_code.strip().upper(), user["email"])
            if ok:
                st.success(f"Joined team '{msg}'!")
                st.rerun()
            else:
                st.error(msg)

def get_contest_state():
    state = contest_col.find_one({"_id": "main"})
    if not state:
        contest_col.insert_one({"_id": "main", "status": "not_started"})
        return "not_started"
    return state["status"]

def set_contest_state(status):
    contest_col.update_one({"_id": "main"}, {"$set": {"status": status}}, upsert=True)
    if status == "not_started":
        # Clear all teams, users (except admin), team_answers, and questions
        users_col.delete_many({"email": {"$ne": ADMIN_EMAIL}})
        teams_col.delete_many({})
        team_answers_col.delete_many({})
        questions_col.delete_many({})
        # Re-create admin and demo questions
        ensure_admin()
        ensure_questions()

def admin_panel():
    st.subheader(":red[Admin Controls]")
    status = get_contest_state()
    st.info(f"Contest status: {status}")
    if status == "not_started":
        if st.button("Start Contest"):
            set_contest_state("running")
            st.success("Contest started!")
            st.rerun()
    elif status == "running":
        if st.button("End Contest"):
            set_contest_state("finished")
            st.success("Contest ended!")
            st.rerun()
    elif status == "finished":
        if st.button("Reset Contest"):
            set_contest_state("not_started")
            st.success("Contest reset!")
            st.rerun()

def ensure_questions():
    if questions_col.count_documents({}) == 0:
        with open("questions.json", "r") as f:
            questions = json.load(f)
        questions_col.insert_many(questions)

def get_team_answers(team_id):
    answers = team_answers_col.find({"team_id": team_id})
    return {a["qnum"]: a for a in answers}

def get_total_attempts(team_id):
    # Sum all attempts for this team
    answers = team_answers_col.find({"team_id": team_id})
    return sum(a.get("attempts", 0) for a in answers)

def submit_answer(team_id, qnum, min_val, max_val, answer):
    if get_contest_state() != "running":
        return False, "Contest has stopped running. Nice try though :) "
    if min_val <= 0 or max_val <= 0:
        return False, "Min and Max cannot be 0 or less."
    if min_val > max_val:
        return False, "Min cannot be greater than Max."
    if get_total_attempts(team_id) >= MAX_ATTEMPTS:
        return False, f"Your team has used all {MAX_ATTEMPTS} attempts. No more submissions allowed."
    team_answers = team_answers_col
    rec = team_answers.find_one({"team_id": team_id, "qnum": qnum})
    correct = (min_val <= answer <= max_val)
    if rec:
        if (rec['correct']):
            if min_val >= rec["min"] and max_val <= rec["max"] and (min_val != rec["min"] or max_val != rec["max"]):
                team_answers.update_one({"_id": rec["_id"]}, {"$set": {"min": min_val, "max": max_val, "correct": correct}, "$inc": {"attempts": 1}})
                return True, "Submitted."
            else:
                return False, "Range is larger than previous correct submission."
        else:
            team_answers.update_one({"_id": rec["_id"]}, {"$set": {"min": min_val, "max": max_val, "correct": correct}, "$inc": {"attempts": 1}})
            return True, "Submitted."
    else:
        team_answers.insert_one({
            "team_id": team_id,
            "qnum": qnum,
            "min": min_val,
            "max": max_val,
            "attempts": 1,
            "correct": correct
        })
        return True, "Submitted."

def team_questions_interface(user):
    team = get_team(user)
    if not team:
        return
    status = get_contest_state()
    if status != "running":
        st.info("Contest is not running.")
        return
    ensure_questions()
    questions = list(questions_col.find({}).sort("qnum", 1))
    answers = get_team_answers(team["_id"])
    total_attempts = get_total_attempts(team["_id"])
    score, wrong, S = compute_team_score(team["_id"])
    st.info(f"Current Team Score: {score}")
    st.header("Questions")
    st.warning(f"Total attempts used: {total_attempts} / {MAX_ATTEMPTS}")
    attempts_left = MAX_ATTEMPTS - total_attempts
    for q in questions:
        qnum = q["qnum"]
        st.markdown(f"**Q{qnum}: {q['text']}**")
        ans = answers.get(qnum)
        if ans:
            if ans["correct"]:
                st.success(f"Correct! Range: [{ans['min']}, {ans['max']}] Attempts used on this question: {ans['attempts']}")
            else:
                st.warning(f"Wrong. Attempts used on this question: {ans['attempts']}")
                st.write(f"Last tried: [{ans['min']}, {ans['max']}]" )
        if attempts_left > 0:
            with st.form(f"form_{qnum}"):
                min_val = st.number_input(f"Min for Q{qnum}", key=f"min_{qnum}")
                max_val = st.number_input(f"Max for Q{qnum}", key=f"max_{qnum}")
                submit = st.form_submit_button("Submit")
                if submit:
                    ok, msg = submit_answer(team["_id"], qnum, min_val, max_val, q["answer"])
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
        else:
            st.info(f"No attempts remaining for your team.")
        st.markdown("---")

def compute_team_score(team_id):
    answers = list(team_answers_col.find({"team_id": team_id}))
    num_questions = len(list(questions_col.find({})))
    wrong = 0
    S = 0
    for a in answers:
        if a.get("correct"):
            S += a["max"]/a["min"]
        else:
            wrong += 1
    wrong += (num_questions - len(answers))
    score = (2 ** (wrong)) * (10 + S)
    return score, wrong, S+10

def show_team_results(user):
    team = get_team(user)
    if not team:
        return
    st.header("Your Team's Results")
    score, wrong, S = compute_team_score(team["_id"])
    st.info(f"Score: {score}")
    st.write(f"Wrong answers: {wrong}")
    st.write(f"Sum of (max/min) for correct answers: {S}")
    answers = list(team_answers_col.find({"team_id": team["_id"]}))
    st.subheader("Breakdown:")
    for a in sorted(answers, key=lambda x: x["qnum"]):
        if a.get("correct"):
            st.success(f"Q{a['qnum']}: Correct, Range: [{a['min']}, {a['max']}] Attempts: {a['attempts']}")
        else:
            st.error(f"Q{a['qnum']}: Wrong after {a['attempts']} attempts. Last tried: [{a['min']}, {a['max']}]" )

def show_leaderboard():
    teams = list(teams_col.find({}))
    results = []
    for team in teams:
        score, wrong, S = compute_team_score(team["_id"])
        attempts = get_total_attempts(team["_id"])
        results.append({"name": team["name"], "score": score, "attempts": attempts, "wrong": wrong, "S+10": S})
    results.sort(key=lambda x: (x["score"], x["attempts"]))
    st.table(results)


def show_live_leaderboard():
    st.header("Live Leaderboard")
    teams = list(teams_col.find({}))
    results = []
    for team in teams:
        score, wrong, S = compute_team_score(team["_id"])
        attempts = get_total_attempts(team["_id"])
        results.append({"name": team["name"], "score": score, "attempts": attempts, "wrong": wrong, "S+10": S})
    results.sort(key=lambda x: (x["score"], x["attempts"]))
    st.table(results)

def main():
    ensure_admin()
    ensure_questions()
    st.set_page_config('Estimathon', '🎯', layout='wide')
    controller = CookieController()
    if "user" not in st.session_state:
        user_cookie = controller.get('estimathon_user')
        if user_cookie:
            user = users_col.find_one({"email": user_cookie})
            if user:
                st.session_state["user"] = user

    st.title("M&T Board x Bridgewater Estimathon")
    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "login"
    if "user" not in st.session_state:
        if st.session_state["auth_mode"] == "login":
            login_form(controller)
        else:
            signup_form()
        return
    user = st.session_state["user"]
    st.sidebar.write(f"Logged in as: {user['email']}")
    if st.sidebar.button("Logout"):
        del st.session_state["user"]
        controller.remove('estimathon_user')
        st.rerun()
    # Admin controls
    if user.get("is_admin"):
        admin_panel()
    # Live leaderboard for admin during contest
    status = get_contest_state()
    if user.get("is_admin") and status == "running":
        show_live_leaderboard()
    # Team management section
    team_management(user)
    # Question answering interface or results
    if status == "finished":
        show_team_results(user)
        if user.get("is_admin"):
            show_leaderboard()
    else:
        team_questions_interface(user)

if __name__ == "__main__":
    main()
