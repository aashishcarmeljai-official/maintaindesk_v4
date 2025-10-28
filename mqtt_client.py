import paho.mqtt.client as mqtt
import socketio
import time
import json
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import MqttConfig, Meter  # Assuming your models.py is accessible
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION ---
# This client needs to know where your Flask-SocketIO server is running
SOCKETIO_URL = 'http://127.0.0.1:5000' # Use the local address Gunicorn is bound to

# This client also needs to connect to the database to get MQTT config and topics
DATABASE_URI = os.getenv("DATABASE_URI")
if not DATABASE_URI:
    raise ValueError("DATABASE_URI environment variable not set!")

# --- SETUP ---
# Standard Python Socket.IO client
sio = socketio.Client()
# Standard SQLAlchemy setup for a script
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
db_session = Session()

# --- MQTT CLIENT CALLBACKS ---

def on_connect(client, userdata, flags, rc):
    """Callback for when the client connects to the MQTT broker."""
    if rc == 0:
        print("Connected successfully to MQTT Broker!")
        # --- Subscribe to all registered meter topics ---
        try:
            meters = db_session.query(Meter).filter_by(is_active=True).all()
            if meters:
                for meter in meters:
                    client.subscribe(meter.mqtt_topic)
                    print(f"Subscribed to topic: {meter.mqtt_topic}")
            else:
                print("No active meters found in the database to subscribe to.")
        except Exception as e:
            print(f"Error querying for meter topics: {e}")
    else:
        print(f"Failed to connect to MQTT Broker, return code {rc}\n")

def on_message(client, userdata, msg):
    """Callback for when a message is received from the broker."""
    print(f"Received message on topic {msg.topic}: {msg.payload.decode()}")
    try:
        # Decode the payload and parse it as JSON
        payload_data = json.loads(msg.payload.decode())
        
        # --- Emit the data over Socket.IO ---
        # We send the message to a 'room' named after the topic.
        # The frontend analytics page joins this room when a user selects a meter.
        sio.emit('forward_mqtt_message', {
            'topic': msg.topic,
            'payload': payload_data
        })
        print(f"Forwarded MQTT message from topic {msg.topic} to Socket.IO server.")
        
    except json.JSONDecodeError:
        print(f"Warning: Could not decode JSON payload from topic {msg.topic}")
    except Exception as e:
        print(f"An error occurred in on_message: {e}")

# --- MAIN EXECUTION ---

def run_mqtt_client():
    """Main function to configure and run the MQTT client."""
    
    # --- Fetch MQTT Config from the database for the FIRST company ---
    # In a multi-company setup, you might run one client per company
    # or have a more complex topic structure. For now, we'll use the first config found.
    mqtt_config = db_session.query(MqttConfig).first()
    if not mqtt_config:
        print("MQTT configuration not found in the database. Exiting.")
        return

    print(f"Using MQTT config for host: {mqtt_config.host}")

    # Create and configure the MQTT client
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    if mqtt_config.username and mqtt_config.password:
        client.username_pw_set(mqtt_config.username, mqtt_config.password)

    # Attempt to connect
    try:
        client.connect(mqtt_config.host, mqtt_config.port, 60)
    except Exception as e:
        print(f"Could not connect to MQTT broker at {mqtt_config.host}:{mqtt_config.port}. Error: {e}")
        return

    # Start the network loop in a non-blocking way
    client.loop_start()
    
    # Connect to the Flask-SocketIO server
    try:
        sio.connect(SOCKETIO_URL)
        print(f"Connected to Socket.IO server at {SOCKETIO_URL}")
    except socketio.exceptions.ConnectionError as e:
        print(f"Could not connect to Socket.IO server. Is it running? Error: {e}")
        client.loop_stop()
        return

    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
    finally:
        client.loop_stop()
        sio.disconnect()
        db_session.close()
        print("Client disconnected.")

if __name__ == '__main__':
    run_mqtt_client()