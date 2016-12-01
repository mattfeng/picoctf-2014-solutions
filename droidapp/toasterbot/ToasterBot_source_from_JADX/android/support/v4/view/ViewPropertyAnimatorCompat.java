package android.support.v4.view;

import android.os.Build.VERSION;
import android.view.View;
import android.view.animation.Interpolator;
import java.lang.ref.WeakReference;

public class ViewPropertyAnimatorCompat {
    static final ViewPropertyAnimatorCompatImpl IMPL;
    private static final String TAG = "ViewAnimatorCompat";
    private WeakReference<View> mView;

    interface ViewPropertyAnimatorCompatImpl {
        void alpha(View view, float f);

        void alphaBy(View view, float f);

        void cancel(View view);

        long getDuration(View view);

        Interpolator getInterpolator(View view);

        long getStartDelay(View view);

        void rotation(View view, float f);

        void rotationBy(View view, float f);

        void rotationX(View view, float f);

        void rotationXBy(View view, float f);

        void rotationY(View view, float f);

        void rotationYBy(View view, float f);

        void scaleX(View view, float f);

        void scaleXBy(View view, float f);

        void scaleY(View view, float f);

        void scaleYBy(View view, float f);

        void setDuration(View view, long j);

        void setInterpolator(View view, Interpolator interpolator);

        void setListener(View view, ViewPropertyAnimatorListener viewPropertyAnimatorListener);

        void setStartDelay(View view, long j);

        void start(View view);

        void translationX(View view, float f);

        void translationXBy(View view, float f);

        void translationY(View view, float f);

        void translationYBy(View view, float f);

        void withEndAction(View view, Runnable runnable);

        void withLayer(View view);

        void withStartAction(View view, Runnable runnable);

        void m0x(View view, float f);

        void xBy(View view, float f);

        void m1y(View view, float f);

        void yBy(View view, float f);
    }

    static class BaseViewPropertyAnimatorCompatImpl implements ViewPropertyAnimatorCompatImpl {
        BaseViewPropertyAnimatorCompatImpl() {
        }

        public void setDuration(View view, long value) {
        }

        public void alpha(View view, float value) {
        }

        public void translationX(View view, float value) {
        }

        public void translationY(View view, float value) {
        }

        public void withEndAction(View view, Runnable runnable) {
            runnable.run();
        }

        public long getDuration(View view) {
            return 0;
        }

        public void setInterpolator(View view, Interpolator value) {
        }

        public Interpolator getInterpolator(View view) {
            return null;
        }

        public void setStartDelay(View view, long value) {
        }

        public long getStartDelay(View view) {
            return 0;
        }

        public void alphaBy(View view, float value) {
        }

        public void rotation(View view, float value) {
        }

        public void rotationBy(View view, float value) {
        }

        public void rotationX(View view, float value) {
        }

        public void rotationXBy(View view, float value) {
        }

        public void rotationY(View view, float value) {
        }

        public void rotationYBy(View view, float value) {
        }

        public void scaleX(View view, float value) {
        }

        public void scaleXBy(View view, float value) {
        }

        public void scaleY(View view, float value) {
        }

        public void scaleYBy(View view, float value) {
        }

        public void cancel(View view) {
        }

        public void m6x(View view, float value) {
        }

        public void xBy(View view, float value) {
        }

        public void m7y(View view, float value) {
        }

        public void yBy(View view, float value) {
        }

        public void translationXBy(View view, float value) {
        }

        public void translationYBy(View view, float value) {
        }

        public void start(View view) {
        }

        public void withLayer(View view) {
        }

        public void withStartAction(View view, Runnable runnable) {
            runnable.run();
        }

        public void setListener(View view, ViewPropertyAnimatorListener listener) {
        }
    }

    static class ICSViewPropertyAnimatorCompatImpl extends BaseViewPropertyAnimatorCompatImpl {

        /* renamed from: android.support.v4.view.ViewPropertyAnimatorCompat.ICSViewPropertyAnimatorCompatImpl.1 */
        class C01021 implements ViewPropertyAnimatorListener {
            final /* synthetic */ Runnable val$runnable;

            C01021(Runnable runnable) {
                this.val$runnable = runnable;
            }

            public void onAnimationStart(View view) {
            }

            public void onAnimationEnd(View view) {
                this.val$runnable.run();
                ICSViewPropertyAnimatorCompatImpl.this.setListener(view, null);
            }

            public void onAnimationCancel(View view) {
            }
        }

        /* renamed from: android.support.v4.view.ViewPropertyAnimatorCompat.ICSViewPropertyAnimatorCompatImpl.2 */
        class C01032 implements ViewPropertyAnimatorListener {
            final /* synthetic */ Runnable val$runnable;

            C01032(Runnable runnable) {
                this.val$runnable = runnable;
            }

            public void onAnimationStart(View view) {
                this.val$runnable.run();
                ICSViewPropertyAnimatorCompatImpl.this.setListener(view, null);
            }

            public void onAnimationEnd(View view) {
            }

            public void onAnimationCancel(View view) {
            }
        }

        /* renamed from: android.support.v4.view.ViewPropertyAnimatorCompat.ICSViewPropertyAnimatorCompatImpl.3 */
        class C01043 implements ViewPropertyAnimatorListener {
            final /* synthetic */ int val$currentLayerType;

            C01043(int i) {
                this.val$currentLayerType = i;
            }

            public void onAnimationStart(View view) {
                ViewCompat.setLayerType(view, 2, null);
            }

            public void onAnimationEnd(View view) {
                ViewCompat.setLayerType(view, this.val$currentLayerType, null);
                ICSViewPropertyAnimatorCompatImpl.this.setListener(view, null);
            }

            public void onAnimationCancel(View view) {
            }
        }

        ICSViewPropertyAnimatorCompatImpl() {
        }

        public void setDuration(View view, long value) {
            ViewPropertyAnimatorCompatICS.setDuration(view, value);
        }

        public void alpha(View view, float value) {
            ViewPropertyAnimatorCompatICS.alpha(view, value);
        }

        public void translationX(View view, float value) {
            ViewPropertyAnimatorCompatICS.translationX(view, value);
        }

        public void translationY(View view, float value) {
            ViewPropertyAnimatorCompatICS.translationY(view, value);
        }

        public long getDuration(View view) {
            return ViewPropertyAnimatorCompatICS.getDuration(view);
        }

        public void setInterpolator(View view, Interpolator value) {
            ViewPropertyAnimatorCompatICS.setInterpolator(view, value);
        }

        public void setStartDelay(View view, long value) {
            ViewPropertyAnimatorCompatICS.setStartDelay(view, value);
        }

        public long getStartDelay(View view) {
            return ViewPropertyAnimatorCompatICS.getStartDelay(view);
        }

        public void alphaBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.alphaBy(view, value);
        }

        public void rotation(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotation(view, value);
        }

        public void rotationBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotationBy(view, value);
        }

        public void rotationX(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotationX(view, value);
        }

        public void rotationXBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotationXBy(view, value);
        }

        public void rotationY(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotationY(view, value);
        }

        public void rotationYBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.rotationYBy(view, value);
        }

        public void scaleX(View view, float value) {
            ViewPropertyAnimatorCompatICS.scaleX(view, value);
        }

        public void scaleXBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.scaleXBy(view, value);
        }

        public void scaleY(View view, float value) {
            ViewPropertyAnimatorCompatICS.scaleY(view, value);
        }

        public void scaleYBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.scaleYBy(view, value);
        }

        public void cancel(View view) {
            ViewPropertyAnimatorCompatICS.cancel(view);
        }

        public void m8x(View view, float value) {
            ViewPropertyAnimatorCompatICS.m4x(view, value);
        }

        public void xBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.xBy(view, value);
        }

        public void m9y(View view, float value) {
            ViewPropertyAnimatorCompatICS.m5y(view, value);
        }

        public void yBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.yBy(view, value);
        }

        public void translationXBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.translationXBy(view, value);
        }

        public void translationYBy(View view, float value) {
            ViewPropertyAnimatorCompatICS.translationYBy(view, value);
        }

        public void start(View view) {
            ViewPropertyAnimatorCompatICS.start(view);
        }

        public void setListener(View view, ViewPropertyAnimatorListener listener) {
            ViewPropertyAnimatorCompatICS.setListener(view, listener);
        }

        public void withEndAction(View view, Runnable runnable) {
            setListener(view, new C01021(runnable));
        }

        public void withStartAction(View view, Runnable runnable) {
            setListener(view, new C01032(runnable));
        }

        public void withLayer(View view) {
            setListener(view, new C01043(ViewCompat.getLayerType(view)));
        }
    }

    static class JBViewPropertyAnimatorCompatImpl extends ICSViewPropertyAnimatorCompatImpl {
        JBViewPropertyAnimatorCompatImpl() {
        }

        public void withStartAction(View view, Runnable runnable) {
            ViewPropertyAnimatorCompatJB.withStartAction(view, runnable);
        }

        public void withEndAction(View view, Runnable runnable) {
            ViewPropertyAnimatorCompatJB.withEndAction(view, runnable);
        }

        public void withLayer(View view) {
            ViewPropertyAnimatorCompatJB.withLayer(view);
        }
    }

    static class JBMr2ViewPropertyAnimatorCompatImpl extends JBViewPropertyAnimatorCompatImpl {
        JBMr2ViewPropertyAnimatorCompatImpl() {
        }

        public Interpolator getInterpolator(View view) {
            return ViewPropertyAnimatorCompatJellybeanMr2.getInterpolator(view);
        }
    }

    ViewPropertyAnimatorCompat(View view) {
        this.mView = new WeakReference(view);
    }

    static {
        int version = VERSION.SDK_INT;
        if (version >= 18) {
            IMPL = new JBMr2ViewPropertyAnimatorCompatImpl();
        } else if (version >= 16) {
            IMPL = new JBViewPropertyAnimatorCompatImpl();
        } else if (version >= 14) {
            IMPL = new ICSViewPropertyAnimatorCompatImpl();
        } else {
            IMPL = new BaseViewPropertyAnimatorCompatImpl();
        }
    }

    public ViewPropertyAnimatorCompat setDuration(long value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.setDuration(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat alpha(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.alpha(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat alphaBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.alphaBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat translationX(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.translationX(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat translationY(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.translationY(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat withEndAction(Runnable runnable) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.withEndAction(view, runnable);
        }
        return this;
    }

    public long getDuration() {
        View view = (View) this.mView.get();
        if (view != null) {
            return IMPL.getDuration(view);
        }
        return 0;
    }

    public ViewPropertyAnimatorCompat setInterpolator(Interpolator value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.setInterpolator(view, value);
        }
        return this;
    }

    public Interpolator getInterpolator() {
        View view = (View) this.mView.get();
        if (view != null) {
            return IMPL.getInterpolator(view);
        }
        return null;
    }

    public ViewPropertyAnimatorCompat setStartDelay(long value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.setStartDelay(view, value);
        }
        return this;
    }

    public long getStartDelay() {
        View view = (View) this.mView.get();
        if (view != null) {
            return IMPL.getStartDelay(view);
        }
        return 0;
    }

    public ViewPropertyAnimatorCompat rotation(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotation(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat rotationBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotationBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat rotationX(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotationX(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat rotationXBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotationXBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat rotationY(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotationY(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat rotationYBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.rotationYBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat scaleX(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.scaleX(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat scaleXBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.scaleXBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat scaleY(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.scaleY(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat scaleYBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.scaleYBy(view, value);
        }
        return this;
    }

    public void cancel() {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.cancel(view);
        }
    }

    public ViewPropertyAnimatorCompat m2x(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.m0x(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat xBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.xBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat m3y(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.m1y(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat yBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.yBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat translationXBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.translationXBy(view, value);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat translationYBy(float value) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.translationYBy(view, value);
        }
        return this;
    }

    public void start() {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.start(view);
        }
    }

    public ViewPropertyAnimatorCompat withLayer() {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.withLayer(view);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat withStartAction(Runnable runnable) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.withStartAction(view, runnable);
        }
        return this;
    }

    public ViewPropertyAnimatorCompat setListener(ViewPropertyAnimatorListener listener) {
        View view = (View) this.mView.get();
        if (view != null) {
            IMPL.setListener(view, listener);
        }
        return this;
    }
}
