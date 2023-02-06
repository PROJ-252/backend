import com.proj252.AIstopwatch.proj252.repository.StopwatchRepo
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
public class SpringConfig {

    private final val stopwatchRepo: StopwatchRepo

    @Autowired
    constructor(stopwatchRepo: StopwatchRepo){
        this.stopwatchRepo = stopwatchRepo
    }
    //beans를 못찾는 다는 에러가 뜬다면 intellij의 문제라고 함, 실제 실행에 문제없다고함

    @Bean
    public fun reportService(): ReportService{
        return ReportService(stopwatchRepo)
    }

}