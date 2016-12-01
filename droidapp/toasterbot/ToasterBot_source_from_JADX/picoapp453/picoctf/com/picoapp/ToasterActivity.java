package picoapp453.picoctf.com.picoapp;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

public class ToasterActivity extends ActionBarActivity {
    String mystery;

    public ToasterActivity() {
        this.mystery = new String(new char[]{'f', 'l', 'a', 'g', ' ', 'i', 's', ':', ' ', 'w', 'h', 'a', 't', '_', 'd', 'o', 'e', 's', '_', 't', 'h', 'e', '_', 'l', 'o', 'g', 'c', 'a', 't', '_', 's', 'a', 'y'});
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) C0090R.layout.activity_my);
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(C0090R.menu.my, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == C0090R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void displayMessage(View view) {
        Toast.makeText(getApplicationContext(), "Toasters don't toast toast, toast toast toast!", 1).show();
        Log.d("Debug tag", this.mystery);
    }
}
