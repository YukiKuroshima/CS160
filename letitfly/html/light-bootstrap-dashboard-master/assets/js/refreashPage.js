refreashPage = {
  /*
   * @param time time is in millisecond
   * 5000 ms = 5 second
   */
  run: function(time) {
    setTimeout(function(){
      window.location.reload(1);
    }, time);
  }
}
