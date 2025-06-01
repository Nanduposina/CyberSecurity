import pandas as pd
import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output
import plotly.express as px
import numpy as np

#  Load dataset
file_path = r"C:\Users\nandu\OneDrive\Documents\Desktop\Threat-Intelligence-Intrusion-Detection-Platform\WEEK-3\CyberIDS-Project\dashboard\dashboard_data.csv"
df = pd.read_csv(file_path)

#  Generate synthetic timestamps if missing
df['Timestamp'] = pd.date_range(start="2025-01-01", periods=len(df), freq="s")

#  Convert timestamp column to datetime format
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Fix attack type column & mapping
if 'Attack_Type' not in df.columns:
    print(" 'Attack_Type' column not found. Checking alternatives...")
    possible_cols = [col for col in df.columns if 'attack' in col.lower() or 'label' in col.lower()]
    if possible_cols:
        df.rename(columns={possible_cols[0]: 'Attack_Type'}, inplace=True)
    else:
        raise KeyError("ERROR: No valid attack classification column found!")

# Convert attack labels to meaningful names
attack_mapping = {0.0: "Benign", 1.0: "Malicious"}  # Modify if more attack types exist
df['Attack_Type'] = df['Attack_Type'].map(attack_mapping)

# Reverse-map standardized protocol values
protocol_mapping = {
    -1.81673562: "TCP",
    -0.47353795: "UDP",
    1.9889911: "ICMP"
}

# Apply the mapping to fix protocol names
df['Protocol'] = df['Protocol'].map(protocol_mapping)

print(df[['Protocol']].head(10))  # Debugging output to confirm mapping worked

# Get unique attack types for dropdown filter
attack_types = df['Attack_Type'].unique()

# Initialize Dash app with Bootstrap styling
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.SLATE])
app.config.suppress_callback_exceptions = True  # Prevents errors for dynamically created components

# Dashboard Layout
app.layout = html.Div([
    dbc.Container([
        html.H1("Intrusion Detection Dashboard", style={'textAlign': 'center', 'color': 'white'}),

        # Search Functionality
        dbc.Row([
            dbc.Col(html.Label("Search Logs by Protocol, Attack Type, or Port:", style={'color': 'white'})),
            dbc.Col(
                dcc.Input(
                    id='search-input',
                    type='text',
                    placeholder="Enter TCP, UDP, ICMP, attack type, or port...",
                    debounce=True,
                    style={'backgroundColor': 'black', 'color': 'white'}
                )
            )
        ], className="mb-3"),
        dbc.Row([dbc.Col(html.Div(id='search-results'))], className="mb-3"),

        # Attack Type Filter Dropdown
        dbc.Row([
            dbc.Col(html.Label("Filter by Attack Type:", style={'color': 'white'})),
            dbc.Col(
                dcc.Dropdown(
                    id='attack-dropdown',
                    options=[{'label': attack, 'value': attack} for attack in attack_types],
                    placeholder="Select an attack type",
                    multi=True,
                    style={'backgroundColor': 'black', 'color': 'white'}
                )
            )
        ], className="mb-3"),
        dbc.Row([dbc.Col(html.Div(id='attack-filter-results'))], className="mb-3"),

        # Graphs for Visualization
        dbc.Row([dbc.Col(dcc.Graph(id='traffic-protocol-chart'))], className="mb-3"),
        dbc.Row([dbc.Col(dcc.Graph(id='detection-rate-chart'))], className="mb-3"),
        dbc.Row([dbc.Col(dcc.Graph(id='attack-trends-chart'))], className="mb-3"),

        # Real-time update interval
        dcc.Interval(
            id='interval-component',
            interval=5000,  # Refresh every 5 seconds
            n_intervals=0
        )
    ])
], style={'backgroundColor': '#222', 'padding': '20px'})

# Callback: Search Functionality
@app.callback(
    Output('search-results', 'children'),
    [Input('search-input', 'value')]
)
def search_logs(search_value):
    if not search_value:
        return html.Div("Enter a query to search logs.", style={'color': 'white'})

    # Search across Protocol, Port, and Attack_Type
    filtered_df = df[df.apply(lambda row: search_value.lower() in str(row.values).lower(), axis=1)]

    print(f"Search Query Received: {search_value}")
    print(filtered_df.head())  # Debugging output

    if filtered_df.empty:
        return html.Div("No matching results found.", style={'color': 'red'})

    return dbc.Table.from_dataframe(filtered_df.head(10), striped=True, bordered=True, hover=True)

# Callback: Attack Type Filtering
@app.callback(
    Output('attack-filter-results', 'children'),
    [Input('attack-dropdown', 'value')]
)
def filter_attack_type(selected_attacks):
    print(f"Dropdown Selection: {selected_attacks}")  # Debugging

    if not selected_attacks:
        return html.Div("Select an attack type to view logs.", style={'color': 'white'})

    filtered_df = df[df['Attack_Type'].isin(selected_attacks)]
    print(filtered_df.head())  # Debugging output

    if filtered_df.empty:
        return html.Div("No matching logs found.", style={'color': 'red'})

    return dbc.Table.from_dataframe(filtered_df.head(10), striped=True, bordered=True, hover=True)

# Callback: Update Traffic by Protocol Chart
@app.callback(
    Output('traffic-protocol-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_traffic_protocol_chart(n_intervals):
    protocol_summary = df.groupby(['Protocol', 'Attack_Type']).size().reset_index(name='Count')
    fig = px.bar(protocol_summary, x='Protocol', y='Count', color='Attack_Type',
                 title="Traffic by Protocol (Benign vs. Malicious)",
                 labels={'Protocol': 'Protocol Type', 'Count': 'Intrusion Count'},
                 template="plotly_dark")
    return fig

# Callback: Update Detection Rate Chart
@app.callback(
    Output('detection-rate-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_detection_rate(n_intervals):
    detection_summary = df['Attack_Type'].value_counts().reset_index()
    fig = px.pie(detection_summary, names='Attack_Type', values='count',
                 title="Detection Rates (Benign vs Malicious)",
                 labels={'Attack_Type': 'Category', 'count': 'Traffic Volume'},
                 template="plotly_dark")
    return fig

# Callback: Update Attack Trends Over Time
@app.callback(
    Output('attack-trends-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_attack_trends(n_intervals):
    attack_trends = df[df['Attack_Type'] == 'Malicious'].groupby(df['Timestamp'].dt.hour).size().reset_index(name='Attack Count')

    fig = px.line(attack_trends, x='Timestamp', y='Attack Count',
                  title="Attack Trends Over Time",
                  labels={'Timestamp': 'Hour of Day', 'Attack Count': 'Number of Attacks'},
                  template="plotly_dark")

    return fig

# Run Dashboard Server
if __name__ == '__main__':
    app.run(debug=True)
