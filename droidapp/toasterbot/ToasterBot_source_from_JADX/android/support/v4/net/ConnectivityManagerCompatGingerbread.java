package android.support.v4.net;

import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.support.v4.app.NotificationCompat.WearableExtender;
import android.support.v4.media.TransportMediator;
import android.support.v4.widget.CursorAdapter;
import android.support.v7.internal.widget.ActionBarView;

class ConnectivityManagerCompatGingerbread {
    ConnectivityManagerCompatGingerbread() {
    }

    public static boolean isActiveNetworkMetered(ConnectivityManager cm) {
        NetworkInfo info = cm.getActiveNetworkInfo();
        if (info == null) {
            return true;
        }
        switch (info.getType()) {
            case ActionBarView.DISPLAY_DEFAULT /*0*/:
            case CursorAdapter.FLAG_REGISTER_CONTENT_OBSERVER /*2*/:
            case WearableExtender.SIZE_MEDIUM /*3*/:
            case TransportMediator.FLAG_KEY_MEDIA_PLAY /*4*/:
            case WearableExtender.SIZE_FULL_SCREEN /*5*/:
            case FragmentManagerImpl.ANIM_STYLE_FADE_EXIT /*6*/:
                return true;
            case CursorAdapter.FLAG_AUTO_REQUERY /*1*/:
                return false;
            default:
                return true;
        }
    }
}
