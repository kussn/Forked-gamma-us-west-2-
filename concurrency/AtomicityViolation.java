package cucumber.helpers.shared;

import com.amazonaws.services.dynamodbv2.LockItem;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class PackageLocksHelper {
    private static final Logger log = LogManager.getLogger(PackageLocksHelper.class);
    private final PackageLock packageLock;
    private final String stage;
    private final Map<String, LockItem> lockedPackages = new ConcurrentHashMap<>();

    public PackageLocksHelper(PackageLock packageLock, String stage) {
        this.packageLock = packageLock;
        this.stage = stage.substring(0, 1).toUpperCase() + stage.substring(1).toLowerCase();
    }

    public String lockGitFarmPackageWithStage(String packagePrefix) {
        int count = this.packageLock.getCountForPackage(packagePrefix);
        List<String> packagePool = IntStream.rangeClosed(1, count)
                .mapToObj(String::valueOf)
                .map(i -> packagePrefix + "-" + stage + i)
                .collect(Collectors.toList());
        return this.lockGitFarmPackage(packagePool);
    }

    public String lockGitFarmPackage(String packagePrefix) {
        int count = this.packageLock.getCountForPackage(packagePrefix);
        List<String> packagePool = IntStream.rangeClosed(1, count)
                .mapToObj(String::valueOf)
                .map(i -> packagePrefix + i)
                .collect(Collectors.toList());
        return this.lockGitFarmPackage(packagePool);
    }

    public String lockGitFarmPackage(List<String> packagePool) {
        try {
            LockItem lockPackage = this.packageLock.getLockedPackage(packagePool);
            String packageName = lockPackage.getSortKey().get();

            this.lockedPackages.put(packageName, lockPackage);
            log.info("A lock is acquired for GitFarm package " + packageName);
            return packageName;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void releaseGitFarmPackage(String packageName) {
        if (!this.lockedPackages.containsKey(packageName)) {
            throw new IllegalArgumentException("The package " + packageName + " is not locked.");
        }
        this.lockedPackages.get(packageName).close();
        this.lockedPackages.remove(packageName);
        log.info("A lock is released for GitFarm package " + packageName);
    }

    public void cleanUp() {
        this.lockedPackages.forEach((packageName, lockPackage) -> lockPackage.close());
        this.lockedPackages.clear();
    }
}