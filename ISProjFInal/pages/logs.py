import streamlit as st
import json
import os
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go


def load_logs():
    """Load logs from the JSON file"""
    log_file = os.path.join('logs', 'auth_logs.json')
    try:
        with open(log_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        st.error("Log file not found!")
        return []
    except json.JSONDecodeError:
        st.error("Error reading log file!")
        return []

def create_log_df(logs):
    """Convert logs to a pandas DataFrame with enhanced vault access tracking"""
    flat_logs = []
    for log in logs:
        flat_log = {
            'id': log['id'],
            'timestamp': datetime.fromisoformat(log['timestamp']),
            'event_type': log['event_type'],
            'username': log['username'],
            'status': log['details'].get('status', 'unknown'),
            'is_vault_access': log['event_type'] == 'vault_access',
            'access_type': log['details'].get('access_type', 'none'),
            'file_accessed': log['details'].get('file_accessed', 'none'),
            'access_duration': log['details'].get('duration_seconds', 0)
        }

        if 'voice_similarity_score' in log['details']:
            flat_log['voice_similarity_score'] = log['details']['voice_similarity_score']
        if 'passphrase_match_score' in log['details']:
            flat_log['passphrase_match_score'] = log['details']['passphrase_match_score']

        flat_logs.append(flat_log)

    return pd.DataFrame(flat_logs)

def display_vault_analytics(df):
    """Display vault-specific analytics"""
    st.header("Vault Access Analytics")

    # Filter for vault access events
    vault_df = df[df['is_vault_access']]

    if len(vault_df) == 0:
        st.warning("No vault access events found in the selected period.")
        return

    # Vault access statistics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Vault Accesses", len(vault_df))
    with col2:
        avg_duration = vault_df['access_duration'].mean()
        st.metric("Avg. Access Duration", f"{avg_duration:.1f}s")
    with col3:
        unique_accessors = vault_df['username'].nunique()
        st.metric("Unique Users", unique_accessors)
    with col4:
        total_duration = vault_df['access_duration'].sum()
        st.metric("Total Access Time", f"{total_duration:.0f}s")

    # Vault access patterns over time
    st.subheader("Vault Access Patterns")
    hourly_access = vault_df.set_index('timestamp').resample('H')['event_type'].count()

    fig_access_pattern = px.line(
        hourly_access,
        title="Hourly Vault Access Frequency",
        labels={'value': 'Number of Accesses', 'timestamp': 'Time'}
    )
    st.plotly_chart(fig_access_pattern)

    # User access distribution
    st.subheader("User Access Distribution")
    user_access = vault_df['username'].value_counts()
    fig_user_dist = px.bar(
        x=user_access.index,
        y=user_access.values,
        title="Vault Access by User",
        labels={'x': 'Username', 'y': 'Number of Accesses'}
    )
    st.plotly_chart(fig_user_dist)

    # Access type distribution
    access_types = vault_df['access_type'].value_counts()
    fig_access_types = px.pie(
        values=access_types.values,
        names=access_types.index,
        title="Access Type Distribution"
    )
    st.plotly_chart(fig_access_types)

    # Most accessed files
    st.subheader("Most Accessed Files")
    file_access = vault_df['file_accessed'].value_counts().head(10)
    fig_files = px.bar(
        x=file_access.index,
        y=file_access.values,
        title="Top 10 Accessed Files",
        labels={'x': 'File Name', 'y': 'Access Count'}
    )
    st.plotly_chart(fig_files)

def main():
    st.title("Voice Authentication System - Log Viewer")

    # Load logs
    logs = load_logs()
    if not logs:
        st.warning("No logs found.")
        return

    # Convert to DataFrame
    df = create_log_df(logs)

    # Sidebar filters
    st.sidebar.header("Filters")

    # Date range filter
    date_min = df['timestamp'].min()
    date_max = df['timestamp'].max()
    date_range = st.sidebar.date_input(
        "Date Range",
        [date_min.date(), date_max.date()]
    )

    # Event type filter
    event_types = ['All'] + list(df['event_type'].unique())
    selected_event = st.sidebar.selectbox("Event Type", event_types)

    # Username filter
    usernames = ['All'] + list(df['username'].unique())
    selected_username = st.sidebar.selectbox("Username", usernames)

    # Status filter
    statuses = ['All'] + list(df['status'].unique())
    selected_status = st.sidebar.selectbox("Status", statuses)

    # Apply filters
    mask = (df['timestamp'].dt.date >= date_range[0]) & \
           (df['timestamp'].dt.date <= date_range[1])

    if selected_event != 'All':
        mask &= df['event_type'] == selected_event
    if selected_username != 'All':
        mask &= df['username'] == selected_username
    if selected_status != 'All':
        mask &= df['status'] == selected_status

    filtered_df = df[mask]

    # Create tabs for different views
    tab1, tab2 = st.tabs(["Authentication Analytics", "Vault Access Analytics"])

    with tab1:
        # Display authentication statistics
        st.header("Authentication Statistics")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Total Events", len(filtered_df))
        with col2:
            success_rate = (filtered_df['status'] == 'success').mean() * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
        with col3:
            unique_users = filtered_df['username'].nunique()
            st.metric("Unique Users", unique_users)

        # Time series plot
        st.subheader("Authentication Events Over Time")
        daily_events = filtered_df.set_index('timestamp') \
            .resample('D')['event_type'].count()

        fig_timeline = px.line(
            daily_events,
            title="Daily Authentication Events"
        )
        st.plotly_chart(fig_timeline)

        # Success/Failure distribution
        st.subheader("Success/Failure Distribution")
        status_dist = filtered_df['status'].value_counts()
        fig_status = px.pie(
            values=status_dist.values,
            names=status_dist.index,
            title="Event Status Distribution"
        )
        st.plotly_chart(fig_status)

        # Event type distribution
        st.subheader("Event Type Distribution")
        event_dist = filtered_df['event_type'].value_counts()
        fig_events = px.bar(
            x=event_dist.index,
            y=event_dist.values,
            title="Event Type Distribution"
        )
        st.plotly_chart(fig_events)

    with tab2:
        display_vault_analytics(filtered_df)

    # Detailed log view
    st.header("Detailed Logs")
    st.dataframe(
        filtered_df.sort_values('timestamp', ascending=False) \
            .reset_index(drop=True)
    )

    # Export functionality
    if st.button("Export Filtered Logs to CSV"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name="voice_auth_logs.csv",
            mime="text/csv"
        )


if __name__ == "__main__":
    main()