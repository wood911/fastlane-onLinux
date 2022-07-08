package tools.fastlane.localetester;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.rules.ActivityScenarioRule;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import tools.fastlane.screengrab.FalconScreenshotStrategy;
import tools.fastlane.screengrab.Screengrab;
import tools.fastlane.screengrab.locale.LocaleTestRule;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;

@RunWith(JUnit4.class)
public class FalconScreenshots {

    @ClassRule
    public static final LocaleTestRule localeTestRule = new LocaleTestRule();

    @Rule
    public ActivityScenarioRule<MainActivity> activityRule = new ActivityScenarioRule<>(MainActivity.class);


    @Test
    public void testTakeScreenshot() {
        activityRule.getScenario().onActivity(new ActivityScenario.ActivityAction<MainActivity>() {
            @Override
            public void perform(MainActivity activity) {
                Screengrab.setDefaultScreenshotStrategy(new FalconScreenshotStrategy(activity));
            }
        });

        onView(withId(R.id.greeting)).check(matches(isDisplayed()));

        Screengrab.screenshot("falcon_beforeFabClick");

        onView(withId(R.id.fab)).perform(click());

        Screengrab.screenshot("falcon_afterFabClick");
    }

    @Test
    public void testTakeMoreScreenshots() {
        activityRule.getScenario().onActivity(new ActivityScenario.ActivityAction<MainActivity>() {
            @Override
            public void perform(MainActivity activity) {
                Screengrab.setDefaultScreenshotStrategy(new FalconScreenshotStrategy(activity));
            }
        });

        onView(withId(R.id.nav_button)).perform(click());

        Screengrab.screenshot("falcon_anotherActivity");

        onView(withId(R.id.show_dialog_button)).perform(click());

        Screengrab.screenshot("falcon_anotherActivity-dialog");

        onView(withText(android.R.string.ok)).perform(click());
    }
}
