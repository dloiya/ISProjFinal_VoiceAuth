import streamlit as st
from connect import getdb

def logout():
    """
    Logs the user out by updating the database and clearing session state.
    """
    if "user" in st.session_state:
        db = getdb()
        users_collection = db["userdata"]
        users_collection.update_one(
            {"username": st.session_state.user["username"]},
            {"$set": {"is_active": False}}
        )
        del st.session_state.user
        st.info("You have been logged out.")

def dashboard():
    """
    Displays the dashboard with options based on user access level.
    """
    if "user" not in st.session_state:
        st.warning("Please log in to access the dashboard.")
        return

    db = getdb()
    user_data = db["userdata"].find_one({"username": st.session_state.user["username"]})

    if user_data:
        st.title(f"Welcome, {st.session_state.user['username']}!")

        user_access_level = st.session_state.user["access"]
        options = ["Open Vault", "Logout"]

        if user_access_level == "admin":
            st.write("You have admin access.")
            options = ["Open Vault", "Register New User", "Open Logs", "Register New Voice", "Logout"]
        else:
            st.write("You have user access.")

        st.subheader("Options")

        selected_option = st.radio("Select an action:", options)

        if st.button("Submit"):
            if selected_option == "Open Vault":
                st.switch_page("pages/piwhotemp.py")
            elif selected_option == "Register New User" and user_access_level == "admin":
                st.switch_page("pages/adduser.py")
            elif selected_option == "Open Logs" and user_access_level == "admin":
                st.switch_page("pages/logs.py")
            elif selected_option == "Register New Voice" and user_access_level == "admin":
                st.switch_page("pages/piwhoadmin.py")
            elif selected_option == "Logout":
                logout()
    else:
        st.warning("Please log in to access the dashboard.")

dashboard()
