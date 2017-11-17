
from flask import Flask, render_template
from flask_googlemaps import GoogleMaps
from flask_googlemaps import Map, icons
import webbrowser

app = Flask(__name__, template_folder="templates")

app.config['GOOGLEMAPS_KEY'] = "AIzaSyAck9gozAKmXvYT3KXbkvYqV8mU9Vs7Qdk"

GoogleMaps(app, key="AIzaSyAck9gozAKmXvYT3KXbkvYqV8mU9Vs7Qdk")


@app.route('/', methods=["GET"])
def fullmap():
    fullmap = Map(
        identifier="fullmap",
        varname="fullmap",
        style=(
            "height:100%;"
            "width:100%;"
            "top:0;"
            "left:0;"
            "position:absolute;"
            "z-index:200;"
        ),
        # hardcoded coordinates to SJSU for now
        lat=37.3352,
        lng=-121.8811,
        markers=[
            {
                'icon': '//maps.google.com/mapfiles/ms/icons/green-dot.png',
                'lat': 37.3352,
                'lng': -121.8811,
                'infobox': "Hello I am <b style='color:green;'>HELLO WORLD GREEN</b>!"
            },
            {
                'icon': '//maps.google.com/mapfiles/ms/icons/blue-dot.png',
                'lat': 37.4300,
                'lng': -122.1400,
                'infobox': "Hello I am <b style='color:blue;'>HELLO WORLD BLUE</b>!"
            },
            {
                'icon': icons.dots.yellow,
                'title': 'Click Here',
                'lat': 37.4500,
                'lng': -122.1350,
                'infobox': (
                    "Hello I am <b style='color:#ffcc00;'>YELLOW</b>!"
                    "<h2>It is HTML title</h2>"
                    "<img src='//placehold.it/50'>"
                    "<br>Images allowed!"
                )
            }
        ],
    )
    return render_template('directory.html', fullmap=fullmap)


if __name__ == "__main__":
    #webbrowser.open('http://127.0.0.1:5000')
    app.run(debug=True, use_reloader=True)
